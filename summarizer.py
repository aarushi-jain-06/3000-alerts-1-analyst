"""
Generates a short shift-handover brief per incident.

Default mode: deterministic template (no API key, no network, no cost --
runs anywhere, including air-gapped SOC environments). This is what most
enterprise SOAR tools ship as their baseline.

Optional mode: if ANTHROPIC_API_KEY is set in the environment, briefs are
rewritten by a Claude model for more natural analyst-facing prose. This is
the "free AI model for the summaries" hook -- swap in any provider here
(Claude, a local Llama build, etc.) without touching the rest of the
pipeline, since scoring/grouping/MITRE mapping are already done upstream.
"""

import os
from assets import asset_info
from rag import context_for_incident

USE_LLM = bool(os.environ.get("ANTHROPIC_API_KEY"))
USE_OLLAMA = bool(os.environ.get("OLLAMA_MODEL"))


def _attack_timeline(incident):
    """Narrate alerts as an ordered arrow-chain: time → type → technique."""
    alerts = sorted(incident.get("alerts", []), key=lambda a: a["timestamp"])
    if not alerts:
        return ""
    steps = []
    for a in alerts:
        ts_short = a["timestamp"][11:16]  # HH:MM
        steps.append(f"{ts_short} [{a['alert_type']} / {a['technique_id']}]")
    return " → ".join(steps)


def _template_brief(incident):
    info = asset_info(incident["asset_id"])
    techniques_str = ", ".join(
        f"{t}" for t in incident["techniques"]
    )
    tactics_str = " -> ".join(incident["tactics"])
    alert_ids_str = ", ".join(incident.get("alert_ids", [])[:10])  # first 10
    if len(incident.get("alert_ids", [])) > 10:
        alert_ids_str += f" (+{len(incident['alert_ids']) - 10} more)"

    timeline = _attack_timeline(incident)
    next_stage = incident.get("predicted_next_stage", "")
    ml_flag = "ML-scored" if incident.get("ml_confidence") else "heuristic-scored"

    brief = (
        f"Incident {incident['incident_id']} ({incident['risk_tier']}, "
        f"score {incident['risk_score']}): {incident['alert_count']} alert(s) "
        f"on {incident['asset_id']} ({info['type']}, {info['criticality']} "
        f"criticality) between {incident['start_time']} and {incident['end_time']}. "
        f"Observed ATT&CK techniques: {techniques_str}. "
        f"Kill-chain stages touched: {tactics_str}. "
        f"Correlation confidence {int(incident['confidence'] * 100)}% ({ml_flag}). "
    )

    if timeline:
        brief += f"\nAttack timeline: {timeline}. "

    if next_stage:
        brief += f"\n⚠ Predicted next stage: {next_stage}. "

    grounded_context = context_for_incident(incident, k=2)
    if grounded_context:
        brief += "\nATT&CK evidence context: " + " | ".join(grounded_context) + " "

    if alert_ids_str:
        brief += f"\nAlert IDs: {alert_ids_str}. "

    brief += "Recommended action: " + _recommendation(incident)
    return brief


def _recommendation(incident):
    tier = incident["risk_tier"]
    if tier == "CRITICAL":
        return ("isolate host immediately, escalate to Tier 2/IR, "
                "and begin credential-reset workflow for any associated accounts.")
    if tier == "HIGH":
        return ("prioritize for immediate analyst review this shift; "
                "pull EDR timeline for the asset before disposition.")
    if tier == "MEDIUM":
        return "review within shift; check for repeat occurrence before closing."
    return "low urgency -- batch review at end of shift or auto-close if pattern is known-benign."


def _llm_brief(incident):
    """Optional path: call the Anthropic API for a more natural-language
    brief. Falls back to the template on any error so the pipeline never
    breaks in production."""
    try:
        import requests
        grounded = context_for_incident(incident, k=3)
        prompt = (
            "You are a SOC shift-handover assistant. Write a 3-4 sentence "
            "incident brief for the next analyst, in plain professional "
            "language. Be concrete and actionable, do not invent facts "
            "beyond what's given. Cite the ATT&CK evidence context when useful.\n\n"
            "ATT&CK evidence context:\n" + "\n".join(grounded) +
            "\n\nIncident data:\n" + str({
                k: v for k, v in incident.items() if k != "alerts"
            })
        )
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": os.environ["ANTHROPIC_API_KEY"],
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15,
        )
        resp.raise_for_status()
        content = resp.json()["content"]
        text = "".join(b.get("text", "") for b in content)
        return text.strip() or _template_brief(incident)
    except Exception:
        return _template_brief(incident)


def _ollama_brief(incident):
    """Optional free/local model path using an Ollama-compatible endpoint."""
    try:
        import requests
        grounded = context_for_incident(incident, k=3)
        prompt = ("Write a concise SOC handover brief using only these facts. "
                  "Do not invent details. ATT&CK context:\n" +
                  "\n".join(grounded) + "\nIncident:\n" + str(incident))
        response = requests.post(
            os.environ.get("OLLAMA_HOST", "http://localhost:11434") + "/api/generate",
            json={"model": os.environ["OLLAMA_MODEL"], "prompt": prompt, "stream": False},
            timeout=30,
        )
        response.raise_for_status()
        text = response.json().get("response", "").strip()
        return text or _template_brief(incident)
    except Exception:
        return _template_brief(incident)


def generate_brief(incident):
    if USE_LLM:
        return _llm_brief(incident)
    if USE_OLLAMA:
        return _ollama_brief(incident)
    return _template_brief(incident)
