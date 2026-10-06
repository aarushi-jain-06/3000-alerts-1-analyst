import csv
import json
import os

from pipeline import run_pipeline
from retrain import retrain_if_ready

OUT_DIR = os.path.join(os.path.dirname(__file__), "outputs")
os.makedirs(OUT_DIR, exist_ok=True)


def write_alerts_csv(alerts, path):
    fields = ["alert_id", "timestamp", "asset_id", "alert_type", "src_ip", "dst_ip",
              "technique_id", "technique_name", "tactic", "base_severity",
              "false_positive_rate"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts)


def write_incidents_json(incidents, path):
    slim = []
    for inc in incidents:
        d = {k: v for k, v in inc.items() if k != "alerts"}
        slim.append(d)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(slim, f, indent=2)


def write_review_queue_csv(queue, path):
    fields = ["incident_id", "risk_tier", "risk_score", "asset_id", "disposition",
              "auto_suggested_disposition", "reviewed_by", "reviewed_at", "notes"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(queue)


def write_shift_brief_md(incidents, metrics, path, top_n=25):
    lines = []
    lines.append("# Shift Handover Brief\n")
    lines.append(f"Alerts ingested: **{metrics['n_alerts']}**  |  "
                 f"Incidents after correlation: **{metrics['n_incidents']}**  |  "
                 f"Noise reduction: **{metrics['noise_reduction_ratio']}x**\n")
    lines.append(f"MTTT (per-alert equivalent): baseline **{metrics['baseline_mttt_per_alert_min']} min** "
                 f"-> pipeline **{metrics['pipeline_mttt_per_alert_min']} min** "
                 f"(**-{metrics['mttt_reduction_pct_per_alert']}%**)\n")
    lines.append(f"Total analyst time this batch: baseline **{metrics['baseline_total_hours']} hrs** "
                 f"-> pipeline **{metrics['pipeline_total_hours']} hrs** "
                 f"(**-{metrics['analyst_time_reduction_pct']}%**)\n")
    lines.append("---\n")
    lines.append(f"## Top {top_n} Incidents by Risk\n")

    tier_counts = {}
    for inc in incidents:
        tier_counts[inc["risk_tier"]] = tier_counts.get(inc["risk_tier"], 0) + 1
    lines.append("**Tier breakdown:** " + ", ".join(
        f"{t}: {c}" for t, c in sorted(tier_counts.items())
    ) + "\n")

    for i, inc in enumerate(incidents[:top_n], 1):
        lines.append(f"### {i}. {inc['incident_id']}  --  {inc['risk_tier']}  (score {inc['risk_score']})\n")
        lines.append(inc["brief"] + "\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_metrics_md(metrics, path):
    lines = [
        "# MTTT Impact Summary\n",
        "| Metric | Baseline (manual, per-alert) | With Pipeline | Change |",
        "|---|---|---|---|",
        f"| Items handled | {metrics['n_alerts']} raw alerts | {metrics['n_incidents']} incident briefs | "
        f"{metrics['noise_reduction_ratio']}x fewer items to review |",
        f"| Mean time to triage (per alert) | {metrics['baseline_mttt_per_alert_min']} min | "
        f"{metrics['pipeline_mttt_per_alert_min']} min | -{metrics['mttt_reduction_pct_per_alert']}% |",
        f"| Total analyst-minutes for this batch | {metrics['baseline_total_minutes']} min "
        f"({metrics['baseline_total_hours']} hrs) | {metrics['pipeline_total_minutes']} min "
        f"({metrics['pipeline_total_hours']} hrs) | -{metrics['analyst_time_reduction_pct']}% |",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_metrics_json(metrics, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


def main():
    result = run_pipeline(total_alerts=3000, n_seeded_chains=6)

    write_alerts_csv(result["alerts"], os.path.join(OUT_DIR, "alerts.csv"))
    write_incidents_json(result["incidents"], os.path.join(OUT_DIR, "incidents.json"))
    write_review_queue_csv(result["review_queue"], os.path.join(OUT_DIR, "review_queue.csv"))
    write_shift_brief_md(result["incidents"], result["metrics"],
                         os.path.join(OUT_DIR, "shift_brief.md"))
    write_metrics_md(result["metrics"], os.path.join(OUT_DIR, "mttt_metrics.md"))
    write_metrics_json(result["metrics"], os.path.join(OUT_DIR, "metrics.json"))
    feedback_status = retrain_if_ready()

    print("=== Pipeline complete ===")
    print(f"Alerts: {result['metrics']['n_alerts']}")
    print(f"Incidents: {result['metrics']['n_incidents']}")
    print(f"Noise reduction ratio: {result['metrics']['noise_reduction_ratio']}x")
    print(f"MTTT per-alert: {result['metrics']['baseline_mttt_per_alert_min']} min -> "
          f"{result['metrics']['pipeline_mttt_per_alert_min']} min "
          f"(-{result['metrics']['mttt_reduction_pct_per_alert']}%)")
    print(f"Total analyst time: {result['metrics']['baseline_total_hours']} hrs -> "
          f"{result['metrics']['pipeline_total_hours']} hrs "
          f"(-{result['metrics']['analyst_time_reduction_pct']}%)")
    print(f"\nOutputs written to: {OUT_DIR}")
    if feedback_status.get("ready"):
        print(f"Feedback calibrator trained on {feedback_status['samples']} analyst labels")


if __name__ == "__main__":
    main()
