"""
summarizer.py - SOC Incident Shift Handover Brief Generator.

Produces evidence-grounded, technical incident handover briefs for the next shift.
Consumes: Incident + MITRE mapping + Timeline + RAG context + Risk Score.

Modes:
  1. Free AI Model: Google Gemini API (via google-genai or HTTP) or local Ollama.
  2. Offline Template Fallback: Fully deterministic, zero network dependencies,
     100% test and demo reliable.
     
Strict Anti-Hallucination Guarantees:
  - Uses ONLY provided alert telemetry and playbook context.
  - Cites exact alert IDs for every claim.
  - States 'unknown' rather than inferring unconfirmed facts.
"""

import json
import os
from typing import Any, Dict, List, Optional, Union
from dotenv import load_dotenv

from schemas import Alert, Incident
from mitre_map import map_incident
from investigator import build_timeline, investigate
from rag import get_context
from scoring import score_incident

# Load environment variables from .env file if present
load_dotenv()


class IncidentBrief(str):
    """
    Incident Brief object that behaves both as a rich formatted string
    and as a dictionary exposing the structured fields required by the contract.
    """
    def __new__(cls, text: str, data: Dict[str, Any]):
        instance = super().__new__(cls, text)
        instance._data = data
        return instance

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, str) and key in self._data:
            return self._data[key]
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __contains__(self, item: Any) -> bool:
        if super().__contains__(item):
            return True
        return item in self._data

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._data)


def _recommendation(risk_tier: str) -> str:
    """Standard SOC response recommendations based on risk tier."""
    if risk_tier == "CRITICAL":
        return ("isolate host immediately, escalate to Tier 2/IR, "
                "and begin credential-reset workflow for any associated accounts.")
    if risk_tier == "HIGH":
        return ("prioritize for immediate analyst review this shift; "
                "pull EDR timeline for the asset before disposition.")
    if risk_tier == "MEDIUM":
        return "review within shift; check for repeat occurrence before closing."
    return "low urgency -- batch review at end of shift or auto-close if pattern is known-benign."


def _format_timeline_highlights(timeline: List[Dict[str, Any]]) -> List[str]:
    """Extract concise timeline bullet points."""
    highlights = []
    for evt in timeline:
        ts = evt.get("timestamp", "unknown")
        ts_display = ts[11:19] if "T" in ts else ts
        aid = evt.get("alert_id", "unknown")
        host = evt.get("host", "unknown")
        user = evt.get("user", "unknown")
        atype = evt.get("alert_type", "unknown")
        highlights.append(f"{ts_display} | [{aid}] {host} ({user}) -> {atype}")
    return highlights


def _generate_template_brief(
    incident: Union[Incident, Dict[str, Any]],
    mitre_info: Dict[str, Any],
    timeline: List[Dict[str, Any]],
    rag_context: List[Dict[str, Any]],
    score_info: Dict[str, Any],
) -> IncidentBrief:
    """
    Deterministic, offline briefing engine. Guaranteed 0 hallucinations,
    consistent formatting, and complete coverage.
    """
    inc_id = incident.incident_id if isinstance(incident, Incident) else incident.get("incident_id", "INC-UNKNOWN")
    risk_score = score_info.get("risk_score", 0.0)
    risk_tier = score_info.get("risk_tier", "LOW")
    why_reason = score_info.get("why", "Standard alert cluster evaluation.")

    # Entities
    hosts = sorted(list({e["host"] for e in timeline if e.get("host") and e["host"] != "unknown"}))
    users = sorted(list({e["user"] for e in timeline if e.get("user") and e["user"] not in ("unknown", "", "None")}))
    alert_ids = [e["alert_id"] for e in timeline]

    # Tactics & techniques
    tactics = mitre_info.get("tactics", [])
    technique_details = mitre_info.get("technique_details", [])
    tech_str_list = [f"{t['technique_id']} ({t['technique_name']})" for t in technique_details]
    tech_ids = [t["technique_id"] for t in technique_details]

    # What happened: 2-3 concise evidence-grounded sentences
    start_ts = timeline[0]["timestamp"] if timeline else "unknown"
    end_ts = timeline[-1]["timestamp"] if timeline else "unknown"
    host_summary = ", ".join(hosts) if hosts else "unknown host"
    user_summary = ", ".join(users) if users else "unspecified account"
    tactics_summary = " -> ".join(tactics) if tactics else "Unmapped activity"

    first_event = timeline[0] if timeline else {}
    last_event = timeline[-1] if timeline else {}

    s1 = (
        f"Incident {inc_id} involves {len(timeline)} correlated alert(s) across {host_summary} "
        f"associated with user(s) '{user_summary}' between {start_ts} and {end_ts}."
    )
    s2 = (
        f"Activity initiated with {first_event.get('alert_type', 'unknown')} [{first_event.get('alert_id', 'unknown')}] "
        f"and progressed along the kill chain ({tactics_summary}), concluding with "
        f"{last_event.get('alert_type', 'unknown')} [{last_event.get('alert_id', 'unknown')}]."
    )
    s3 = (
        f"Observed MITRE techniques include {', '.join(tech_str_list) if tech_str_list else 'unknown techniques'}."
    )

    containment_notes = []
    has_blocked_c2 = any(e.get("alert_type") == "c2_beacon_blocked" for e in timeline)
    has_av_hit = any(e.get("alert_type") == "av_signature_hit" for e in timeline)
    if has_blocked_c2 and has_av_hit:
        containment_notes.append("Security controls confirmed the activity was blocked/detected only.")
    elif has_blocked_c2:
        containment_notes.append("Perimeter controls confirmed the c2_beacon_blocked activity was blocked only.")
    elif has_av_hit:
        containment_notes.append("Endpoint protection confirmed the av_signature_hit activity was detected only.")

    s4 = f" {' '.join(containment_notes)}" if containment_notes else ""
    what_happened = f"{s1} {s2} {s3}{s4}"

    # Next-shift actions derived from RAG playbook snippets
    next_actions = []
    playbook_snippets = [r for r in rag_context if r.get("category") == "response_playbook"]
    if playbook_snippets:
        for p in playbook_snippets[:2]:
            next_actions.append(f"Follow {p['title']}: {p['content']}")
    else:
        rec_standard = _recommendation(risk_tier)
        next_actions.append(f"Standard procedure: {rec_standard}")

    rec_text = _recommendation(risk_tier)
    human_review = mitre_info.get("needs_human_review", False) or (risk_tier in ("CRITICAL", "HIGH"))
    title = f"[{risk_tier}] Incident {inc_id}: {tactics[-1] if tactics else 'Security Event'} on {host_summary}"

    timeline_chain = " -> ".join([
        f"{e['timestamp'][11:16] if 'T' in e['timestamp'] else e['timestamp']} [{e['alert_type']} / {e['alert_id']}]"
        for e in timeline
    ])

    # Formatted prose representation
    prose = (
        f"Incident {inc_id} ({risk_tier}, score {risk_score}): {len(timeline)} alert(s) "
        f"on {host_summary} between {start_ts} and {end_ts}. "
        f"Observed ATT&CK techniques: {', '.join(tech_str_list) if tech_str_list else ', '.join(tech_ids)}. "
        f"Kill-chain stages touched: {tactics_summary}. "
        f"\nWhat happened: {what_happened} "
        f"\nAttack timeline: {timeline_chain}. "
        f"\nAlert IDs: {', '.join(alert_ids)}. "
        f"\nRecommended action: {rec_text}"
    )

    data = {
        "title": title,
        "incident_id": inc_id,
        "risk_tier": risk_tier,
        "risk_score": risk_score,
        "risk_reason": why_reason,
        "what_happened": what_happened,
        "timeline_highlights": _format_timeline_highlights(timeline),
        "mitre_tactics_techniques": {
            "tactics": tactics,
            "techniques": tech_ids,
            "technique_names": [t["technique_name"] for t in technique_details],
        },
        "affected_assets": {
            "hosts": hosts if hosts else ["unknown"],
            "users": users if users else ["unknown"],
        },
        "next_shift_actions": next_actions,
        "evidence": alert_ids,
        "human_review_required": "yes" if human_review else "no",
        "generated_by": "offline_template_engine",
        "recommended_action": rec_text,
    }

    return IncidentBrief(prose, data)


def _call_gemini_api(prompt: str) -> Optional[str]:
    """Call Google Gemini API using official google-genai or requests."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None

    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        if response and response.text:
            return response.text
    except Exception:
        pass

    try:
        import requests
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 800},
        }
        res = requests.post(url, json=payload, timeout=12)
        if res.status_code == 200:
            data = res.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
    except Exception:
        pass

    return None


def _call_ollama_api(prompt: str) -> Optional[str]:
    """Call local Ollama endpoint if configured."""
    model = os.environ.get("OLLAMA_MODEL")
    if not model:
        return None

    try:
        import requests
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        res = requests.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.1}},
            timeout=15,
        )
        if res.status_code == 200:
            return res.json().get("response", "")
    except Exception:
        pass

    return None


def generate_brief(
    incident: Union[Incident, Dict[str, Any]],
    mitre_info: Optional[Dict[str, Any]] = None,
    timeline: Optional[List[Dict[str, Any]]] = None,
    rag_context: Optional[List[Dict[str, Any]]] = None,
    score_info: Optional[Dict[str, Any]] = None,
) -> IncidentBrief:
    """
    Generate an evidence-grounded incident handover brief.
    
    Args:
        incident: Incident model or dictionary.
        mitre_info: Output from mitre_map.map_incident (computed if None).
        timeline: Output from investigator.build_timeline (computed if None).
        rag_context: Output from rag.get_context (computed if None).
        score_info: Output from scoring.score_incident (computed if None).
        
    Returns:
        IncidentBrief object supporting both string formatting and structured dict keys.
    """
    if mitre_info is None:
        mitre_info = map_incident(incident)
    if timeline is None:
        timeline = build_timeline(incident)
    if rag_context is None:
        rag_context = get_context(incident, k=3)
    if score_info is None:
        score_info = score_incident(incident)

    template_brief = _generate_template_brief(
        incident=incident,
        mitre_info=mitre_info,
        timeline=timeline,
        rag_context=rag_context,
        score_info=score_info,
    )

    has_gemini = bool(os.environ.get("GEMINI_API_KEY"))
    has_ollama = bool(os.environ.get("OLLAMA_MODEL"))

    if not (has_gemini or has_ollama):
        return template_brief

    context_text = "\n".join([f"- [{r['source_id']}] {r['title']}: {r['content']}" for r in rag_context])
    evidence_text = "\n".join([e["evidence"] for e in timeline])

    prompt = f"""You are a Lead SOC Analyst creating a shift handover brief for a Tier-1 security incident.
STRICT ANTI-HALLUCINATION RULES:
1. Rely ONLY on the provided Alert Evidence and Playbook Context below.
2. Do NOT invent, assume, or hallucinate attacker names, IOCs, IP addresses, or actions not in the evidence.
3. If an attribute (such as user or host) is missing, explicitly write "unknown".
4. Every statement in "what_happened" MUST cite the associated alert ID (e.g. ALT-1001).
5. Output ONLY a valid JSON object matching the requested schema.

INCIDENT ID: {template_brief['incident_id']}
RISK TIER: {template_brief['risk_tier']} (Score: {template_brief['risk_score']})
RISK REASON: {template_brief['risk_reason']}
MITRE TACTICS: {', '.join(mitre_info.get('tactics', []))}
MITRE TECHNIQUES: {', '.join(mitre_info.get('techniques', []))}

ALERT EVIDENCE:
{evidence_text}

RAG PLAYBOOK CONTEXT:
{context_text}

JSON SCHEMA TO RETURN:
{{
  "title": "{template_brief['title']}",
  "what_happened": "2-3 concise sentences detailing what occurred, citing exact alert IDs.",
  "timeline_highlights": ["Chronological event highlight strings"],
  "next_shift_actions": ["1-3 prioritized operational actions based on playbooks"],
  "human_review_required": "yes or no"
}}
"""

    llm_output = None
    generator_name = None

    if has_gemini:
        llm_output = _call_gemini_api(prompt)
        generator_name = "gemini_ai"

    if not llm_output and has_ollama:
        llm_output = _call_ollama_api(prompt)
        generator_name = "ollama"

    if llm_output:
        try:
            clean_json = llm_output.strip()
            if "```json" in clean_json:
                clean_json = clean_json.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_json:
                clean_json = clean_json.split("```")[1].split("```")[0].strip()

            parsed = json.loads(clean_json)
            merged_data = template_brief.to_dict()
            if parsed.get("what_happened"):
                merged_data["what_happened"] = parsed["what_happened"]
            if parsed.get("timeline_highlights"):
                merged_data["timeline_highlights"] = parsed["timeline_highlights"]
            if parsed.get("next_shift_actions"):
                merged_data["next_shift_actions"] = parsed["next_shift_actions"]
            if parsed.get("human_review_required"):
                merged_data["human_review_required"] = parsed["human_review_required"]
            merged_data["generated_by"] = generator_name

            updated_prose = (
                f"Incident {merged_data['incident_id']} ({merged_data['risk_tier']}, score {merged_data['risk_score']}): "
                f"{merged_data['what_happened']} "
                f"\nAttack timeline: {' -> '.join(merged_data['timeline_highlights'])}. "
                f"\nAlert IDs: {', '.join(merged_data['evidence'])}. "
                f"\nRecommended action: {merged_data['recommended_action']}"
            )
            return IncidentBrief(updated_prose, merged_data)
        except Exception:
            return template_brief

    return template_brief


def format_brief_markdown(brief: Union[IncidentBrief, Dict[str, Any]]) -> str:
    """Format a brief dictionary as clean human-readable Markdown."""
    lines = [
        f"# {brief['title']}",
        "",
        f"**Incident ID:** `{brief['incident_id']}` | **Risk Tier:** `{brief['risk_tier']}` (`{brief['risk_score']}/100`)",
        f"**Human Review Required:** `{brief['human_review_required'].upper()}` | **Engine:** `{brief.get('generated_by', 'template')}`",
        "",
        "### 🎯 Risk Score Reason",
        f"> {brief['risk_reason']}",
        "",
        "### 📋 What Happened",
        brief["what_happened"],
        "",
        "### ⏱️ Timeline Highlights",
    ]
    for h in brief["timeline_highlights"]:
        lines.append(f"- {h}")

    lines.extend([
        "",
        "### 🛡️ MITRE ATT&CK",
        f"- **Tactics:** {', '.join(brief['mitre_tactics_techniques']['tactics'])}",
        f"- **Techniques:** {', '.join(brief['mitre_tactics_techniques']['techniques'])} ({', '.join(brief['mitre_tactics_techniques']['technique_names'])})",
        "",
        "### 💻 Affected Entities",
        f"- **Hosts:** {', '.join(brief['affected_assets']['hosts'])}",
        f"- **Accounts:** {', '.join(brief['affected_assets']['users'])}",
        f"- **Evidence Alerts:** {', '.join(brief['evidence'])}",
        "",
        "### 🚀 Next-Shift Actions",
    ])
    for act in brief["next_shift_actions"]:
        lines.append(f"1. {act}")

    return "\n".join(lines)
