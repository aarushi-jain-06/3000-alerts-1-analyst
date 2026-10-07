"""
Unit tests for schemas.py (Alert and Incident data models).
"""

import pytest
from pydantic import ValidationError
from schemas import Alert, Incident


def test_alert_creation_valid():
    alert = Alert(
        alert_id="ALT-001",
        timestamp="2026-10-07T08:00:00Z",
        alert_type="brute_force",
        severity=4,
        host="AUTH-SRV-01",
        user="asmith",
        src_ip="198.51.100.4",
        dst_ip="10.0.1.5",
        description="Repeated failed logon attempts",
        asset_criticality=5,
    )
    assert alert.alert_id == "ALT-001"
    assert alert.severity == 4
    assert alert.asset_criticality == 5
    assert alert.host == "AUTH-SRV-01"


def test_alert_severity_validation_out_of_range():
    with pytest.raises(ValidationError):
        Alert(
            alert_id="ALT-002",
            timestamp="2026-10-07T08:00:00Z",
            alert_type="phishing",
            severity=6,  # Invalid: must be 1-5
            host="WKSTN-1",
            user="user1",
            description="Phish",
            asset_criticality=3,
        )

    with pytest.raises(ValidationError):
        Alert(
            alert_id="ALT-003",
            timestamp="2026-10-07T08:00:00Z",
            alert_type="phishing",
            severity=0,  # Invalid
            host="WKSTN-1",
            user="user1",
            description="Phish",
            asset_criticality=3,
        )


def test_alert_criticality_validation_out_of_range():
    with pytest.raises(ValidationError):
        Alert(
            alert_id="ALT-004",
            timestamp="2026-10-07T08:00:00Z",
            alert_type="phishing",
            severity=3,
            host="WKSTN-1",
            user="user1",
            description="Phish",
            asset_criticality=10,  # Invalid: must be 1-5
        )


def test_incident_properties_and_deserialization():
    raw_dict = {
        "incident_id": "INC-TEST-01",
        "alerts": [
            {
                "alert_id": "A1",
                "timestamp": "2026-10-07T08:00:00Z",
                "alert_type": "brute_force",
                "severity": 3,
                "host": "HOST-A",
                "user": "alice",
                "src_ip": "1.1.1.1",
                "dst_ip": "2.2.2.2",
                "description": "desc 1",
                "asset_criticality": 3,
            },
            {
                "alert_id": "A2",
                "timestamp": "2026-10-07T08:15:00Z",
                "alert_type": "lateral_movement",
                "severity": 5,
                "host": "HOST-B",
                "user": "alice",
                "src_ip": "2.2.2.2",
                "dst_ip": "3.3.3.3",
                "description": "desc 2",
                "asset_criticality": 5,
            },
        ],
    }

    inc = Incident.from_dict(raw_dict)
    assert inc.incident_id == "INC-TEST-01"
    assert inc.alert_count == 2
    assert inc.hosts == ["HOST-A", "HOST-B"]
    assert inc.users == ["alice"]
    assert inc.max_severity == 5
    assert inc.max_criticality == 5
    assert inc.start_time == "2026-10-07T08:00:00Z"
    assert inc.end_time == "2026-10-07T08:15:00Z"
