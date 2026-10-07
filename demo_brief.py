"""
demo_brief.py - End-to-End Demonstration Script.

Runs the complete 'MITRE, Summaries, Investigation' pipeline on the
sample incidents dataset (3 realistic multi-stage incidents + 1 FP cluster).
Demonstrates:
  1. MITRE ATT&CK mapping with kill-chain stage ordering & human review flags.
  2. TF-IDF local RAG retrieval for technique and playbook context.
  3. Investigation timeline and attack path reconstruction.
  4. Narrative-grounded risk scoring with explainable 'why' breakdown.
  5. Shift handover brief generation (AI or deterministic offline fallback).
  6. Mean-Time-To-Triage (MTTT) reduction metrics.
"""

import json
import os
import sys

from schemas import Alert, Incident
from mitre_map import map_incident
from rag import get_context
from investigator import investigate, build_timeline
from scoring import score_incident
from summarizer import generate_brief, format_brief_markdown
from metrics import record_triage_comparison


def load_sample_incidents(json_path: str):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    incidents = []
    for item in data:
        inc = Incident.from_dict(item)
        incidents.append(inc)
    return incidents


def run_demo():
    sample_file = os.path.join(os.path.dirname(__file__), "sample_data", "sample_incidents.json")
    if not os.path.exists(sample_file):
        print(f"Error: Sample data file not found at {sample_file}")
        sys.exit(1)

    print("=" * 80)
    print("3,000 ALERTS, ONE ANALYST - INCIDENT BRIEF & INVESTIGATION DEMO")
    print("=" * 80)
    print(f"Loading sample incidents from: {sample_file}")

    incidents = load_sample_incidents(sample_file)
    print(f"Loaded {len(incidents)} incidents successfully.\n")

    all_alerts = []
    scored_incidents = []
    briefs = []

    for idx, inc in enumerate(incidents, 1):
        all_alerts.extend(inc.alerts)
        print("-" * 80)
        print(f"PROCESSING INCIDENT {idx}/{len(incidents)}: {inc.incident_id}")
        print(f"Hosts: {', '.join(inc.hosts)} | Alerts: {inc.alert_count} | Max Criticality: {inc.max_criticality}/5")
        print("-" * 80)

        # 1. MITRE ATT&CK Mapping
        mitre_info = map_incident(inc)
        print(f"[MITRE Mapping] Tactics: {' -> '.join(mitre_info['tactics'])}")
        print(f"[MITRE Mapping] Techniques: {', '.join(mitre_info['techniques'])}")
        if mitre_info["needs_human_review"]:
            print(f"[MITRE Mapping] ⚠️ Human Review Required: {'; '.join(mitre_info['review_reasons'])}")

        # 2. Local TF-IDF RAG Retrieval
        rag_context = get_context(inc, k=2)
        print(f"[Local RAG] Retrieved {len(rag_context)} playbook snippet(s):")
        for ctx in rag_context:
            print(f"   * [{ctx['source_id']}] {ctx['title']} (Score: {ctx['score']})")

        # 3. Investigation & Timeline
        trace = investigate(inc)
        print(f"[Investigation] Attack Path: {trace['attack_path']}")
        print(f"[Investigation] Duration: {trace['duration_seconds']}s across {len(trace['timeline'])} timeline event(s)")

        # 4. Risk Scoring
        score_info = score_incident(inc)
        scored_incidents.append(score_info)
        print(f"[Risk Scoring] Tier: {score_info['risk_tier']} | Score: {score_info['risk_score']}/100")
        print(f"[Risk Scoring] Rationale: {score_info['why']}")

        # 5. Brief Generation
        brief = generate_brief(
            incident=inc,
            mitre_info=mitre_info,
            timeline=trace["timeline"],
            rag_context=rag_context,
            score_info=score_info,
        )
        briefs.append(brief)

        print("\n" + "~" * 40 + " GENERATED BRIEF " + "~" * 40)
        md_output = format_brief_markdown(brief)
        print(md_output)
        print("~" * 97 + "\n")

    # 6. Mean-Time-To-Triage Metrics Comparison
    metrics = record_triage_comparison(all_alerts, scored_incidents)
    print("=" * 80)
    print("📈 MEAN-TIME-TO-TRIAGE (MTTT) EFFICIENCY REPORT")
    print("=" * 80)
    print(f"Total Raw Alerts Ingested : {metrics['n_alerts']}")
    print(f"Consolidated Incidents    : {metrics['n_incidents']}")
    print(f"Noise Reduction Ratio     : {metrics['noise_reduction_ratio']}x consolidation")
    print(f"Manual Baseline Time      : {metrics['baseline_total_minutes']} mins ({metrics['baseline_total_hours']} hrs)")
    print(f"Pipeline Triage Time      : {metrics['pipeline_total_minutes']} mins ({metrics['pipeline_total_hours']} hrs)")
    print(f"Total Time Saved          : {metrics['time_saved_minutes']} mins ({metrics['time_saved_hours']} hrs)")
    print(f"Analyst Efficiency Boost  : {metrics['efficiency_multiplier']}x faster triage")
    print(f"MTTT Reduction Percentage : {metrics['analyst_time_reduction_pct']}% overall time reduction!")
    print("=" * 80)

    # Save output demo briefs
    out_dir = os.path.join(os.path.dirname(__file__), "outputs")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "demo_shift_briefs.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# Shift Handover Incident Briefs (Demo Output)\n\n")
        for b in briefs:
            f.write(format_brief_markdown(b))
            f.write("\n\n---\n\n")
    print(f"\nSaved full handover briefs markdown report to: {out_path}\n")


if __name__ == "__main__":
    run_demo()
