"""
Unit tests for metrics.py (Mean-Time-To-Triage comparison).
"""

from schemas import Alert, Incident
from metrics import summarize_metrics, record_triage_comparison


def test_record_triage_comparison_demonstrates_savings():
    alerts = [
        Alert(
            alert_id=f"ALT-{i}",
            timestamp="2026-10-07T08:00:00Z",
            alert_type="brute_force" if i % 2 == 0 else "lateral_movement",
            severity=4,
            host=f"HOST-{i}",
            user="user1",
            description="desc",
            asset_criticality=4,
        )
        for i in range(10)
    ]

    incidents = [
        Incident(incident_id="INC-1", alerts=alerts[:5]),
        Incident(incident_id="INC-2", alerts=alerts[5:]),
    ]

    metrics = record_triage_comparison(alerts, incidents)

    assert metrics["n_alerts"] == 10
    assert metrics["n_incidents"] == 2
    assert metrics["noise_reduction_ratio"] == 5.0
    assert metrics["baseline_total_minutes"] > metrics["pipeline_total_minutes"]
    assert metrics["time_saved_minutes"] > 0
    assert metrics["analyst_time_reduction_pct"] > 50.0
    assert metrics["efficiency_multiplier"] > 1.0
