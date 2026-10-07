"""
Unit tests for investigator.py (Timeline, Attack Path, Investigation Traces).
"""

from schemas import Alert, Incident
from investigator import build_timeline, detect_attack_path, investigate


def test_build_timeline_order():
    inc = Incident(
        incident_id="INC-TIME-01",
        alerts=[
            Alert(
                alert_id="A3",
                timestamp="2026-10-07T08:30:00Z",
                alert_type="lateral_movement",
                severity=5,
                host="DC-01",
                user="admin",
                description="PsExec execution",
                asset_criticality=5,
            ),
            Alert(
                alert_id="A1",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="brute_force",
                severity=3,
                host="AUTH-01",
                user="admin",
                description="Failed logins",
                asset_criticality=3,
            ),
            Alert(
                alert_id="A2",
                timestamp="2026-10-07T08:15:00Z",
                alert_type="successful_login",
                severity=2,
                host="AUTH-01",
                user="admin",
                description="Success login",
                asset_criticality=3,
            ),
        ],
    )

    timeline = build_timeline(inc)
    assert len(timeline) == 3
    assert timeline[0]["alert_id"] == "A1"
    assert timeline[1]["alert_id"] == "A2"
    assert timeline[2]["alert_id"] == "A3"


def test_detect_attack_path_and_entities():
    inc = Incident(
        incident_id="INC-PATH-01",
        alerts=[
            Alert(
                alert_id="A1",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="brute_force",
                severity=3,
                host="AUTH-01",
                user="admin",
                src_ip="198.51.100.2",
                dst_ip="10.0.1.5",
                description="Failed auth",
                asset_criticality=3,
            ),
            Alert(
                alert_id="A2",
                timestamp="2026-10-07T08:20:00Z",
                alert_type="lateral_movement",
                severity=5,
                host="DC-01",
                user="admin",
                src_ip="10.0.1.5",
                dst_ip="10.0.0.1",
                description="Pivot to DC",
                asset_criticality=5,
            ),
        ],
    )

    path_data = detect_attack_path(inc)
    assert path_data["affected_assets"] == ["AUTH-01", "DC-01"]
    assert path_data["affected_users"] == ["admin"]
    assert "198.51.100.2" in path_data["src_ips"]
    assert "10.0.0.1" in path_data["dst_ips"]
    assert any("LATERAL PIVOT" in t for t in path_data["transitions"])


def test_investigate_trace_structure():
    inc = Incident(
        incident_id="INC-TRACE-01",
        alerts=[
            Alert(
                alert_id="A1",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="phishing",
                severity=3,
                host="WKSTN-1",
                user="user1",
                description="Phish",
                asset_criticality=2,
            )
        ],
    )

    trace = investigate(inc)
    assert trace["incident_id"] == "INC-TRACE-01"
    assert "timeline" in trace
    assert "attack_path" in trace
    assert "affected_assets" in trace
    assert "steps" in trace
    assert len(trace["steps"]) > 0
