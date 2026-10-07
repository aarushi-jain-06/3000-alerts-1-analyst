"""
Unit tests for rag.py (Local TF-IDF RAG retrieval).
"""

from schemas import Alert, Incident
from rag import get_context, retrieve, context_for_incident


def test_get_context_returns_snippets_with_source_ids():
    inc = Incident(
        incident_id="INC-RAG-01",
        alerts=[
            Alert(
                alert_id="A1",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="brute_force",
                severity=4,
                host="AUTH-01",
                user="jsmith",
                description="Repeated failed Kerberos logins followed by password guessing",
                asset_criticality=4,
            )
        ],
    )

    context = get_context(inc, k=2)
    assert len(context) > 0
    assert len(context) <= 2
    top = context[0]
    assert "source_id" in top
    assert "title" in top
    assert "content" in top
    assert top["source_id"].startswith("MITRE-") or top["source_id"].startswith("PLAYBOOK-")
    assert any("brute" in c["content"].lower() or "brute" in c["title"].lower() for c in context)


def test_get_context_phishing_playbook():
    inc = Incident(
        incident_id="INC-RAG-02",
        alerts=[
            Alert(
                alert_id="A1",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="phishing",
                severity=3,
                host="WKSTN-22",
                user="alice",
                description="Malicious invoice email attachment opened",
                asset_criticality=2,
            )
        ],
    )
    context = get_context(inc, k=3)
    source_ids = [c["source_id"] for c in context]
    assert any("1566" in sid or "phishing" in c["title"].lower() for sid, c in zip(source_ids, context))


def test_retrieve_backward_compat():
    results = retrieve("lateral movement SMB", k=2)
    assert len(results) > 0
    assert isinstance(results[0], str)
    assert "[" in results[0]  # has [source_id]
