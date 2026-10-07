"""
metrics.py - Mean-Time-To-Triage (MTTT) and SOC Efficiency Metrics.

Compares analyst triage time without the tool (manual alert-by-alert triage)
versus with the tool (grouped incident briefs, prioritized ranking, and RAG).
"""

from typing import Any, Dict, List, Tuple, Union
from schemas import Alert, Incident

BASELINE_MINUTES_PER_ALERT = {
    # Legacy & synthetic types
    "failed_logon_spike": 3.0,
    "impossible_travel_login": 5.0,
    "powershell_encoded_cmd": 6.0,
    "new_scheduled_task": 4.0,
    "registry_run_key_mod": 4.0,
    "lsass_access": 8.0,
    "port_scan_detected": 3.0,
    "c2_beacon_blocked": 7.0,
    "dns_tunneling_suspected": 6.0,
    "ransomware_note_created": 10.0,
    "av_signature_hit": 2.0,
    "usb_device_inserted": 2.0,
    "vpn_geo_anomaly": 4.0,
    # Core Hackathon types
    "brute_force": 5.0,
    "successful_login": 3.0,
    "phishing": 6.0,
    "phishing_attachment": 7.0,
    "malware_execution": 8.0,
    "privilege_escalation": 8.0,
    "lateral_movement": 10.0,
    "c2_beaconing": 7.0,
    "data_exfiltration": 12.0,
    "exfiltration": 12.0,
}

MINUTES_PER_INCIDENT_REVIEW = {
    "CRITICAL": 12,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 1.5,
}


def baseline_mttt_minutes(alerts: List[Union[Alert, Dict[str, Any]]]) -> Tuple[float, float]:
    """Calculate total and average minutes required for manual alert triage."""
    if not alerts:
        return 0.0, 0.0
    total = 0.0
    for a in alerts:
        atype = a.alert_type if isinstance(a, Alert) else a.get("alert_type", "")
        total += BASELINE_MINUTES_PER_ALERT.get(atype, 4.0)
    avg_per_alert = total / len(alerts)
    return total, avg_per_alert


def pipeline_mttt_minutes(
    scored_incidents: List[Union[Incident, Dict[str, Any]]],
    queue_scan_overhead_min: float = 0.25,
) -> Tuple[float, float, int]:
    """
    Calculate total analyst minutes required when using the automated incident briefs.
    """
    total = 0.0
    total_alerts_covered = 0
    for inc in scored_incidents:
        if isinstance(inc, Incident):
            tier = getattr(inc, "risk_tier", "MEDIUM")
            count = inc.alert_count
        else:
            tier = inc.get("risk_tier", "MEDIUM")
            count = inc.get("alert_count", len(inc.get("alerts", [])))

        per_incident = MINUTES_PER_INCIDENT_REVIEW.get(tier, 3.0) + queue_scan_overhead_min
        total += per_incident
        total_alerts_covered += count

    avg_per_alert_covered = total / total_alerts_covered if total_alerts_covered else 0.0
    return total, avg_per_alert_covered, total_alerts_covered


def summarize_metrics(
    alerts: List[Union[Alert, Dict[str, Any]]],
    scored_incidents: List[Union[Incident, Dict[str, Any]]],
) -> Dict[str, Any]:
    """Generate comprehensive before/after metrics summary."""
    n_alerts = len(alerts)
    n_incidents = len(scored_incidents)
    if n_alerts == 0 or n_incidents == 0:
        return {
            "n_alerts": n_alerts,
            "n_incidents": n_incidents,
            "noise_reduction_ratio": 1.0,
            "analyst_time_reduction_pct": 0.0,
        }

    baseline_total, baseline_per_alert = baseline_mttt_minutes(alerts)
    new_total, new_per_alert, alerts_covered = pipeline_mttt_minutes(scored_incidents)

    reduction_total_pct = round((1.0 - (new_total / baseline_total)) * 100.0, 1) if baseline_total > 0 else 0.0
    reduction_per_alert_pct = round((1.0 - (new_per_alert / baseline_per_alert)) * 100.0, 1) if baseline_per_alert > 0 else 0.0

    return {
        "n_alerts": n_alerts,
        "n_incidents": n_incidents,
        "noise_reduction_ratio": round(n_alerts / max(1, n_incidents), 1),
        "baseline_total_minutes": round(baseline_total, 1),
        "baseline_total_hours": round(baseline_total / 60.0, 2),
        "baseline_mttt_per_alert_min": round(baseline_per_alert, 2),
        "pipeline_total_minutes": round(new_total, 1),
        "pipeline_total_hours": round(new_total / 60.0, 2),
        "pipeline_mttt_per_alert_min": round(new_per_alert, 2),
        "mttt_reduction_pct_per_alert": reduction_per_alert_pct,
        "analyst_time_reduction_pct": reduction_total_pct,
    }


def record_triage_comparison(
    alerts: List[Union[Alert, Dict[str, Any]]],
    incidents: List[Union[Incident, Dict[str, Any]]],
) -> Dict[str, Any]:
    """
    Convenience function to measure triage time with vs without the tool.
    Returns clear comparison stats and time savings.
    """
    summary = summarize_metrics(alerts, incidents)
    time_saved_min = round(summary["baseline_total_minutes"] - summary["pipeline_total_minutes"], 1)
    time_saved_hrs = round(time_saved_min / 60.0, 2)
    return {
        **summary,
        "time_saved_minutes": max(0.0, time_saved_min),
        "time_saved_hours": max(0.0, time_saved_hrs),
        "efficiency_multiplier": round(summary["baseline_total_minutes"] / max(0.1, summary["pipeline_total_minutes"]), 1),
    }
