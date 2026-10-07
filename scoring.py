"""
scoring.py - Narrative-Tied Risk Scoring Engine.

Score = f(asset_criticality, max_severity, alert_count, mitre_stage, confidence)

- asset_criticality: CMDB weight (1-10) or alert asset_criticality mapping
- max_severity: worst alert base_severity (1-10) in the incident
- alert_count: capped volume factor min(1 + 0.02 * (count - 1), 1.3)
- mitre_stage / chain_bonus: multi-stage attack bonus (up to 1.5x)
- confidence: ML probability when available, or 1 - avg_false_positive_rate
- Returns score AND a human-readable 'why' breakdown.
"""

from typing import Any, Dict, List, Optional, Union
from schemas import Alert, Incident
from mitre_map import map_incident

try:
    from assets import criticality_weight, asset_info
except ImportError:
    def criticality_weight(asset_id: str) -> int:
        return 4
    def asset_info(asset_id: str) -> dict:
        return {"type": "Unknown", "criticality": "MEDIUM"}

# Try to load ML model — fallback if not available
try:
    from ml_classifier import predict_malicious_proba_batch, is_available as _ml_available
    _USE_ML = _ml_available()
except ImportError:
    _USE_ML = False

TACTIC_STAGE_ORDER = [
    "Initial Access", "Execution", "Discovery", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def predict_next_stage(tactics_observed: List[str]) -> str:
    """Predict the likely next kill-chain stage given observed tactics."""
    if not tactics_observed:
        return "Unknown"

    max_idx = -1
    for t in tactics_observed:
        for idx, stage in enumerate(TACTIC_STAGE_ORDER):
            if stage.lower() in t.lower() or t.lower() in stage.lower():
                if idx > max_idx:
                    max_idx = idx

    if max_idx == -1:
        return "Unknown"
    if max_idx >= len(TACTIC_STAGE_ORDER) - 1:
        return "Impact already reached — potential data destruction / ransomware"

    return TACTIC_STAGE_ORDER[max_idx + 1]


def _kill_chain_bonus(tactics: List[str]) -> float:
    """Multi-stage kill chain bonus."""
    n_tactics = len(tactics)
    if n_tactics >= 3:
        return 1.5
    if n_tactics == 2:
        return 1.2
    return 1.0


def _confidence(alerts: List[Any]) -> float:
    """Compute confidence from false positive rates or ML model."""
    fp_rates = []
    for a in alerts:
        if isinstance(a, Alert):
            # Map severity/criticality to approximate FP prior
            fp = 0.10 if a.severity >= 5 else (0.20 if a.severity == 4 else (0.35 if a.severity == 3 else 0.60))
            fp_rates.append(fp)
        elif isinstance(a, dict):
            fp = a.get("false_positive_rate")
            if fp is None:
                sev = a.get("severity", a.get("base_severity", 3))
                fp = 0.10 if sev >= 5 else 0.40
            fp_rates.append(fp)

    static_conf = round(1.0 - (sum(fp_rates) / max(1, len(fp_rates))), 3)

    if _USE_ML:
        try:
            probas = predict_malicious_proba_batch(alerts)
            valid = [p for p in probas if p is not None]
            if valid:
                ml_avg = sum(valid) / len(valid)
                if ml_avg > 0.5:
                    boost = (ml_avg - 0.5) * 0.40
                    return round(min(static_conf + boost, 0.99), 3)
        except Exception:
            pass

    return max(0.05, static_conf)


def is_benign_alert(alert: Union[Alert, Dict[str, Any]]) -> bool:
    """Detect if an alert is benign (e.g. Authorized USB) and cannot raise risk score."""
    if isinstance(alert, Alert):
        atype = (alert.alert_type or "").lower().strip()
        desc = (alert.description or "").lower()
    elif isinstance(alert, dict):
        if alert.get("is_benign") is True:
            return True
        atype = str(alert.get("alert_type", "") or "").lower().strip()
        desc = str(alert.get("description", "") or "").lower()
    else:
        return False

    if atype in ("authorized_usb", "authorized_usb_device", "authorized_usb_inserted"):
        return True
    if "usb" in atype and any(w in desc for w in ["authoriz", "approv", "whitelist", "benign", "standard peripheral", "mouse", "keyboard"]):
        return True
    if any(w in desc for w in ["authorized usb", "approved usb", "whitelisted usb"]):
        return True
    return False


def score_incident(cluster: Union[Incident, Dict[str, Any]]) -> Dict[str, Any]:
    """Score an incident using asset criticality, severity, kill chain, and volume."""
    if isinstance(cluster, Incident):
        raw_alerts = cluster.alerts
        inc_id = cluster.incident_id
        cluster_dict = cluster.to_dict()
        tactics = []
    else:
        raw_alerts = cluster.get("alerts", [])
        inc_id = cluster.get("incident_id", "INC-UNKNOWN")
        cluster_dict = cluster
        tactics = cluster.get("tactics", [])

    # Filter out benign alerts (e.g. Authorized USB) so they cannot raise risk score
    actionable_alerts = [a for a in raw_alerts if not is_benign_alert(a)]

    # Extract assets
    assets = cluster_dict.get("impacted_assets", cluster_dict.get("assets"))
    if not assets:
        extracted_hosts = set()
        target_pool = actionable_alerts if actionable_alerts else raw_alerts
        for a in target_pool:
            h = a.host if isinstance(a, Alert) else a.get("host", a.get("asset_id"))
            if h:
                extracted_hosts.add(h)
        if not extracted_hosts and "asset_id" in cluster_dict:
            extracted_hosts.add(cluster_dict["asset_id"])
        assets = sorted(list(extracted_hosts)) or ["UNKNOWN-HOST"]
    elif actionable_alerts:
        # If assets was explicitly provided in cluster_dict, exclude any host that exclusively appears in benign alerts
        benign_hosts = {
            a.host if isinstance(a, Alert) else a.get("host", a.get("asset_id"))
            for a in raw_alerts if is_benign_alert(a)
        }
        act_hosts = {
            a.host if isinstance(a, Alert) else a.get("host", a.get("asset_id"))
            for a in actionable_alerts
        }
        only_benign_hosts = benign_hosts - act_hosts
        if only_benign_hosts and act_hosts:
            effective_assets = [h for h in assets if h not in only_benign_hosts]
            if effective_assets:
                assets = effective_assets

    if not actionable_alerts:
        # All alerts in the cluster are benign
        return {
            **cluster_dict,
            "incident_id": inc_id,
            "asset_criticality_weight": 1,
            "impacted_assets": assets,
            "assets": assets,
            "max_severity": 1,
            "confidence": 0.95,
            "ml_confidence": False,
            "chain_bonus": 1.0,
            "volume_factor": 1.0,
            "alert_count": len(raw_alerts),
            "predicted_next_stage": "None (Benign Activity)",
            "tactics": [],
            "risk_score": 0.0,
            "risk_tier": "LOW",
            "why": "Tier LOW (score 0.0): All alerts in cluster are verified benign/authorized (e.g. approved USB peripherals). No attack risk.",
            "score_breakdown": {
                "asset_criticality": 1,
                "asset_criticality_weight": 1,
                "max_severity": 1,
                "base_severity": 1,
                "distinct_assets_count": len(assets),
                "asset_spread_multiplier": 1.0,
                "alert_count": len(raw_alerts),
                "confidence": 0.95,
                "chain_bonus": 1.0,
                "volume_factor": 1.0,
                "predicted_next_stage": "None (Benign Activity)",
                "reasons": ["All alerts in cluster are benign/authorized operations."],
            },
        }

    # Asset criticality weight (1-10 scale)
    weights = []
    for aid in assets:
        w = criticality_weight(aid)
        weights.append(w)
    for a in actionable_alerts:
        ac = a.asset_criticality if isinstance(a, Alert) else a.get("asset_criticality")
        if ac:
            mapped_w = 10 if ac == 5 else (7 if ac == 4 else (4 if ac == 3 else (2 if ac == 2 else 1)))
            weights.append(mapped_w)

    asset_w = max(weights) if weights else 4

    # Max severity strictly from actionable alerts
    severities = []
    for a in actionable_alerts:
        if isinstance(a, Alert):
            severities.append(a.severity * 2)  # scale 1-5 to 2-10
        elif isinstance(a, dict):
            if "base_severity" in a:
                severities.append(a["base_severity"])
            elif "severity" in a:
                s = a["severity"]
                severities.append(s * 2 if s <= 5 else s)
            else:
                severities.append(5)
    max_sev = max(severities) if severities else 5

    # Tactics resolution strictly from actionable alerts
    if not tactics:
        mitre_res = map_incident({"alerts": actionable_alerts})
        tactics = mitre_res["tactics"]

    confidence = _confidence(actionable_alerts)
    chain_bonus = _kill_chain_bonus(tactics)
    alert_count = len(actionable_alerts)
    volume_factor = min(1.0 + 0.02 * max(0, alert_count - 1), 1.3)

    raw_score = asset_w * max_sev * confidence * chain_bonus * volume_factor
    final_score = round(raw_score, 2)
    next_stage = predict_next_stage(tactics)
    tier = risk_tier(final_score)

    raw_crits = [a.asset_criticality if isinstance(a, Alert) else a.get("asset_criticality") for a in actionable_alerts]
    valid_crits = [c for c in raw_crits if c is not None]
    scale_1_to_5_crit = max(valid_crits) if valid_crits else (5 if asset_w >= 10 else (4 if asset_w >= 7 else (3 if asset_w >= 4 else 1)))

    raw_sevs = [a.severity if isinstance(a, Alert) else a.get("severity") for a in actionable_alerts]
    valid_sevs = [s for s in raw_sevs if s is not None]
    scale_1_to_5_sev = max(valid_sevs) if valid_sevs else max(1, min(5, round(max_sev / 2.0)))

    why_reasons = [
        f"Asset criticality: {scale_1_to_5_crit}/5 (weight {asset_w}/10) on target asset(s): {', '.join(assets)}.",
        f"Max alert severity: {scale_1_to_5_sev}/5 (base {max_sev}/10) observed.",
        f"Kill-chain progression bonus: {chain_bonus}x across {len(tactics)} tactic(s).",
        f"Volume factor: {round(volume_factor, 2)}x ({alert_count} alerts consolidated, capped at 1.3x).",
        f"Confidence factor: {round(confidence, 3)} based on domain priors.",
    ]
    why_summary = (
        f"Tier {tier} (score {final_score}) due to criticality {scale_1_to_5_crit}/5 on {', '.join(assets)}, "
        f"severity {scale_1_to_5_sev}/5, touching {len(tactics)} tactic(s) ({', '.join(tactics) if tactics else 'none'})."
    )

    result = {
        **cluster_dict,
        "incident_id": inc_id,
        "asset_criticality_weight": asset_w,
        "impacted_assets": assets,
        "assets": assets,
        "max_severity": max_sev,
        "confidence": confidence,
        "ml_confidence": _USE_ML,
        "chain_bonus": chain_bonus,
        "volume_factor": round(volume_factor, 2),
        "alert_count": alert_count,
        "predicted_next_stage": next_stage,
        "tactics": tactics,
        "risk_score": final_score,
        "risk_tier": tier,
        "why": why_summary,
        "score_breakdown": {
            "asset_criticality": scale_1_to_5_crit,
            "asset_criticality_weight": asset_w,
            "max_severity": scale_1_to_5_sev,
            "base_severity": max_sev,
            "distinct_assets_count": len(assets),
            "asset_spread_multiplier": 1.4 if len(assets) >= 3 else (1.25 if len(assets) == 2 else 1.0),
            "alert_count": alert_count,
            "confidence": confidence,
            "chain_bonus": chain_bonus,
            "volume_factor": round(volume_factor, 2),
            "predicted_next_stage": next_stage,
            "reasons": why_reasons,
        },
    }

    return result


def score_and_rank(clusters: List[Union[Incident, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Score and rank incidents in descending order of risk."""
    scored = [score_incident(c) for c in clusters]
    scored.sort(key=lambda c: c["risk_score"], reverse=True)
    return scored


def risk_tier(score: float, max_possible: float = 10 * 10 * 1.0 * 1.5 * 1.3) -> str:
    """Calculate categorical risk tier (CRITICAL, HIGH, MEDIUM, LOW)."""
    pct = score / max_possible
    if pct >= 0.45:
        return "CRITICAL"
    if pct >= 0.25:
        return "HIGH"
    if pct >= 0.10:
        return "MEDIUM"
    return "LOW"
