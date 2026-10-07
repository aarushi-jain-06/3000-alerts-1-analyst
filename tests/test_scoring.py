"""
Unit tests for scoring.py (Risk Scoring and Narrative Breakdown).
"""

from schemas import Alert, Incident
from scoring import score_incident, score_and_rank, risk_tier


def test_scoring_weights_asset_criticality_and_stage():
    # Low-criticality early stage
    inc_low = Incident(
        incident_id="INC-LOW",
        alerts=[
            Alert(
                alert_id="A1",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="port_scan_detected",
                severity=1,
                host="KIOSK-01",
                user="unknown",
                description="Port scan on kiosk",
                asset_criticality=1,
            )
        ],
    )

    # High-criticality late stage
    inc_high = Incident(
        incident_id="INC-HIGH",
        alerts=[
            Alert(
                alert_id="A2",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="data_exfiltration",
                severity=5,
                host="CORE-DB-01",
                user="SYSTEM",
                description="Massive outbound data exfiltration",
                asset_criticality=5,
            )
        ],
    )

    score_low = score_incident(inc_low)
    score_high = score_incident(inc_high)

    assert score_high["risk_score"] > score_low["risk_score"]
    assert score_high["risk_tier"] in ("CRITICAL", "HIGH")
    assert score_low["risk_tier"] in ("LOW", "MEDIUM")


def test_scoring_breakdown_contains_why_reasons():
    inc = Incident(
        incident_id="INC-BREAKDOWN",
        alerts=[
            Alert(
                alert_id="A1",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="brute_force",
                severity=3,
                host="AUTH-SRV",
                user="jsmith",
                description="Brute force",
                asset_criticality=3,
            ),
            Alert(
                alert_id="A2",
                timestamp="2026-10-07T08:15:00Z",
                alert_type="lateral_movement",
                severity=5,
                host="DC-01",
                user="jsmith",
                description="Lateral to DC",
                asset_criticality=5,
            ),
        ],
    )

    result = score_incident(inc)
    assert "why" in result
    assert "score_breakdown" in result
    breakdown = result["score_breakdown"]
    assert breakdown["asset_criticality"] == 5
    assert breakdown["max_severity"] == 5
    assert breakdown["distinct_assets_count"] == 2
    assert breakdown["asset_spread_multiplier"] > 1.0
    assert len(breakdown["reasons"]) >= 4


def test_score_and_rank_orders_descending():
    inc1 = Incident(
        incident_id="INC-1",
        alerts=[Alert(alert_id="A1", timestamp="T1", alert_type="port_scan_detected", severity=1, host="H1", user="u", description="d", asset_criticality=1)]
    )
    inc2 = Incident(
        incident_id="INC-2",
        alerts=[Alert(alert_id="A2", timestamp="T2", alert_type="lateral_movement", severity=5, host="H2", user="u", description="d", asset_criticality=5)]
    )

    ranked = score_and_rank([inc1, inc2])
    assert ranked[0]["incident_id"] == "INC-2"
    assert ranked[1]["incident_id"] == "INC-1"
