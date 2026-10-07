"""
Unit tests for summarizer.py (Brief Generation and Anti-Hallucination guarantees).
"""

from schemas import Alert, Incident
from summarizer import generate_brief, format_brief_markdown


def test_generate_brief_required_fields():
    inc = Incident(
        incident_id="INC-SUM-01",
        alerts=[
            Alert(
                alert_id="ALT-101",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="brute_force",
                severity=3,
                host="AUTH-SRV-01",
                user="asmith",
                description="Repeated failed authentications",
                asset_criticality=3,
            ),
            Alert(
                alert_id="ALT-102",
                timestamp="2026-10-07T08:10:00Z",
                alert_type="successful_login",
                severity=2,
                host="AUTH-SRV-01",
                user="asmith",
                description="Successful login following failures",
                asset_criticality=3,
            ),
            Alert(
                alert_id="ALT-103",
                timestamp="2026-10-07T08:20:00Z",
                alert_type="lateral_movement",
                severity=5,
                host="DC-01",
                user="asmith",
                description="PsExec remote session to DC-01",
                asset_criticality=5,
            ),
        ],
    )

    brief = generate_brief(inc)

    # Verify all required brief fields
    required_keys = [
        "title",
        "risk_score",
        "risk_reason",
        "what_happened",
        "timeline_highlights",
        "mitre_tactics_techniques",
        "affected_assets",
        "next_shift_actions",
        "evidence",
        "human_review_required",
    ]
    for key in required_keys:
        assert key in brief, f"Missing required brief key: {key}"

    # Anti-hallucination verification
    assert "ALT-101" in brief["evidence"]
    assert "ALT-102" in brief["evidence"]
    assert "ALT-103" in brief["evidence"]
    assert "DC-01" in brief["affected_assets"]["hosts"]
    assert "AUTH-SRV-01" in brief["affected_assets"]["hosts"]
    assert "asmith" in brief["affected_assets"]["users"]


def test_format_brief_markdown():
    inc = Incident(
        incident_id="INC-SUM-02",
        alerts=[
            Alert(
                alert_id="ALT-201",
                timestamp="2026-10-07T09:00:00Z",
                alert_type="phishing",
                severity=3,
                host="WKSTN-FIN-1",
                user="bob",
                description="Phishing invoice opened",
                asset_criticality=2,
            )
        ],
    )
    brief = generate_brief(inc)
    md = format_brief_markdown(brief)

    assert f"# {brief['title']}" in md
    assert "INC-SUM-02" in md
    assert "Next-Shift Actions" in md
    assert "Timeline Highlights" in md
    assert "ALT-201" in md
