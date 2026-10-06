"""
Risk scoring for grouped incidents.

Score = f(asset_criticality, max_severity, technique_diversity, confidence)

- asset_criticality: pulled from the CMDB weight (1-10)
- max_severity: worst single alert's base_severity in the cluster (1-10)
- technique_diversity: number of DISTINCT ATT&CK techniques observed --
  a multi-stage chain (recon -> exec -> persistence -> impact) is far more
  dangerous than five copies of the same alert, even at equal volume.
- confidence: ML model P(malicious) when available; falls back to
  1 - avg_false_positive_rate from the static alert-type table.

Alert COUNT alone is intentionally given very little weight: a printer
throwing 40 duplicate low-severity alerts should never outrank a domain
controller with 3 alerts spanning credential access + persistence.
"""

from assets import criticality_weight

# Try to load ML model — silently use static fallback if not ready
try:
    from ml_classifier import predict_malicious_proba_batch, is_available as _ml_available
    _USE_ML = _ml_available()
except ImportError:
    _USE_ML = False

TACTIC_STAGE_ORDER = [
    "Initial Access", "Discovery", "Execution", "Persistence",
    "Defense Evasion / Initial Access", "Credential Access",
    "Command and Control", "Impact",
]


def _confidence(cluster):
    """
    Confidence that the incident is genuinely malicious (not noise).

    Strategy: ML-BOOST HYBRID
    ─────────────────────────────────────────────────────────────────
    Domain-expert FP rates (static baseline) are the reliable floor —
    they encode decades of SOC experience per alert type and produce
    the correct tier distribution.

    The CICIDS2017-trained ML model supplements this: when it signals
    high maliciousness (proba > 0.5), it boosts confidence by up to +20%.
    When ML is uncertain or low (proba <= 0.5), no adjustment is made —
    the proxy features are inherently approximate for synthetic alerts,
    so we don't let them penalise legitimate threat clusters.

    Net effect:
      - High-severity multi-stage attacks on critical assets → boosted
      - Low-FP ransomware/LSASS already near 0.95 → stays near 0.95
      - USB/port-scan noise → unchanged by ML (static FP already low)
    """
    # Static baseline (always available, domain-calibrated)
    fp_rates    = [a["false_positive_rate"] for a in cluster["alerts"]]
    static_conf = round(1 - sum(fp_rates) / len(fp_rates), 3)

    if _USE_ML:
        try:
            probas = predict_malicious_proba_batch(cluster["alerts"])
            valid  = [p for p in probas if p is not None]
            if valid:
                ml_avg = sum(valid) / len(valid)
                # Only boost when ML is confident (proba > 0.5)
                # Max boost: +0.20 (when proba = 1.0)
                if ml_avg > 0.5:
                    boost  = (ml_avg - 0.5) * 0.40   # maps (0.5,1.0] → (0, 0.20]
                    hybrid = min(static_conf + boost, 0.99)
                    return round(hybrid, 3)
        except Exception:
            pass

    return static_conf


def _kill_chain_bonus(cluster):
    """Extra weight when techniques span multiple distinct attack stages
    (a real chain), vs. many alerts of the same single stage."""
    n_tactics = len(cluster["tactics"])
    if n_tactics >= 3:
        return 1.5
    if n_tactics == 2:
        return 1.2
    return 1.0


def predict_next_stage(tactics_observed: list) -> str:
    """
    Given the list of tactics already observed in an incident,
    predict the likely next kill-chain stage using the canonical
    ATT&CK kill-chain order.

    Returns a descriptive string for inclusion in the incident brief.
    """
    if not tactics_observed:
        return "Unknown"

    # Find the highest stage already reached
    max_stage_idx = -1
    for tactic in tactics_observed:
        if tactic in TACTIC_STAGE_ORDER:
            idx = TACTIC_STAGE_ORDER.index(tactic)
            if idx > max_stage_idx:
                max_stage_idx = idx

    if max_stage_idx == -1:
        return "Unknown"
    if max_stage_idx >= len(TACTIC_STAGE_ORDER) - 1:
        return "Impact already reached — potential data destruction / ransomware"

    next_stage = TACTIC_STAGE_ORDER[max_stage_idx + 1]
    return next_stage


def score_incident(cluster):
    assets = cluster.get("assets", [cluster["asset_id"]])
    # For cross-asset incidents, the most critical impacted asset determines
    # priority.  This prevents lateral movement onto a domain controller from
    # being diluted by the originating workstation.
    asset_w = max(criticality_weight(asset_id) for asset_id in assets)
    max_sev = max(a["base_severity"] for a in cluster["alerts"])
    confidence = _confidence(cluster)
    chain_bonus = _kill_chain_bonus(cluster)
    volume_factor = min(1 + 0.02 * (cluster["alert_count"] - 1), 1.3)  # capped, low weight

    raw_score = asset_w * max_sev * confidence * chain_bonus * volume_factor
    return {
        **cluster,
        "asset_criticality_weight": asset_w,
        "impacted_assets": assets,
        "max_severity": max_sev,
        "confidence": confidence,
        "ml_confidence": _USE_ML,          # flag: True = ML-derived, False = static
        "chain_bonus": chain_bonus,
        "predicted_next_stage": predict_next_stage(cluster["tactics"]),
        "risk_score": round(raw_score, 2),
    }


def score_and_rank(clusters):
    scored = [score_incident(c) for c in clusters]
    scored.sort(key=lambda c: c["risk_score"], reverse=True)
    return scored


def risk_tier(score, max_possible=10 * 10 * 1.0 * 1.5 * 1.3):
    pct = score / max_possible
    if pct >= 0.45:
        return "CRITICAL"
    if pct >= 0.25:
        return "HIGH"
    if pct >= 0.10:
        return "MEDIUM"
    return "LOW"
