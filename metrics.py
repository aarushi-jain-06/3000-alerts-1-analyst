"""
Mean-Time-To-Triage (MTTT) measurement.

BEFORE (baseline): analyst manually opens and dispositions every raw
alert one at a time. Time-per-alert varies by how much investigation it
needs; we model it with alert_type-specific minutes (industry-typical
tier-1 SOC handle times, adjustable).

AFTER (this pipeline): analyst reviews one BRIEF per incident (which may
bundle many raw alerts) plus a fixed queue-scan overhead. LOW-risk/likely
-false-positive incidents below the confidence threshold are flagged for
fast bulk-close rather than individual review.
"""

BASELINE_MINUTES_PER_ALERT = {
    "failed_logon_spike": 3,
    "impossible_travel_login": 5,
    "powershell_encoded_cmd": 6,
    "new_scheduled_task": 4,
    "registry_run_key_mod": 4,
    "lsass_access": 8,
    "port_scan_detected": 3,
    "c2_beacon_blocked": 7,
    "dns_tunneling_suspected": 6,
    "ransomware_note_created": 10,
    "av_signature_hit": 2,
    "usb_device_inserted": 2,
    "vpn_geo_anomaly": 4,
}

MINUTES_PER_INCIDENT_REVIEW = {
    "CRITICAL": 12,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 1.5,   # bulk-scan / confirm-and-close
}


def baseline_mttt_minutes(alerts):
    total = sum(BASELINE_MINUTES_PER_ALERT.get(a["alert_type"], 4) for a in alerts)
    return total, total / len(alerts)


def pipeline_mttt_minutes(scored_incidents, queue_scan_overhead_min=0.25):
    """Analyst time = per-incident review time (varies by tier) + a small
    fixed overhead per incident for scanning the queue entry itself."""
    total = 0.0
    total_alerts_covered = 0
    for inc in scored_incidents:
        per_incident = MINUTES_PER_INCIDENT_REVIEW[inc["risk_tier"]] + queue_scan_overhead_min
        total += per_incident
        total_alerts_covered += inc["alert_count"]
    avg_per_alert_covered = total / total_alerts_covered if total_alerts_covered else 0
    return total, avg_per_alert_covered, total_alerts_covered


def summarize_metrics(alerts, scored_incidents):
    baseline_total, baseline_per_alert = baseline_mttt_minutes(alerts)
    new_total, new_per_alert, alerts_covered = pipeline_mttt_minutes(scored_incidents)

    reduction_total_pct = round((1 - new_total / baseline_total) * 100, 1)
    reduction_per_alert_pct = round((1 - new_per_alert / baseline_per_alert) * 100, 1)

    return {
        "n_alerts": len(alerts),
        "n_incidents": len(scored_incidents),
        "noise_reduction_ratio": round(len(alerts) / len(scored_incidents), 1),
        "baseline_total_minutes": round(baseline_total, 1),
        "baseline_total_hours": round(baseline_total / 60, 1),
        "baseline_mttt_per_alert_min": round(baseline_per_alert, 2),
        "pipeline_total_minutes": round(new_total, 1),
        "pipeline_total_hours": round(new_total / 60, 1),
        "pipeline_mttt_per_alert_min": round(new_per_alert, 2),
        "mttt_reduction_pct_per_alert": reduction_per_alert_pct,
        "analyst_time_reduction_pct": reduction_total_pct,
    }
