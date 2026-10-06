"""
End-to-end pipeline:
  ingest -> correlate/group -> score & rank -> map MITRE -> brief ->
  human-review queue -> MTTT metrics
"""

from alert_generator import generate_alerts
from grouping import group_alerts_into_incidents
from scoring import score_and_rank, risk_tier
from summarizer import generate_brief
from human_loop import build_review_queue
from metrics import summarize_metrics
from investigator import investigate


def run_pipeline(total_alerts=3000, n_seeded_chains=6, seed=42):
    # 1. Ingest
    alerts = generate_alerts(total=total_alerts, n_chains=n_seeded_chains, seed=seed)

    # 2. Correlate raw alerts into candidate incidents
    clusters = group_alerts_into_incidents(alerts)

    # 3. Risk score + rank (asset criticality, severity, kill-chain span)
    scored = score_and_rank(clusters)
    for inc in scored:
        inc["risk_tier"] = risk_tier(inc["risk_score"])

    # Expensive/interactive investigation is gated to incidents an analyst
    # would actually prioritize.
    for inc in scored:
        inc["investigation_trace"] = investigate(inc)

    # 4. Generate a brief per incident (MITRE-mapped, human-readable)
    for inc in scored:
        inc["brief"] = generate_brief(inc)

    # 5. Push to human-in-the-loop review queue (nothing auto-remediates)
    review_queue = build_review_queue(scored)

    # 6. Measure MTTT before/after
    metrics = summarize_metrics(alerts, scored)

    return {
        "alerts": alerts,
        "incidents": scored,
        "review_queue": review_queue,
        "metrics": metrics,
    }


if __name__ == "__main__":
    result = run_pipeline()
    print(f"Alerts: {len(result['alerts'])}  Incidents: {len(result['incidents'])}")
    print(result["metrics"])
