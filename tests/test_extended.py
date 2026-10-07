"""
tests/test_extended.py — Extended QA test suite for the SOC Alert Triage Pipeline.
Covers gaps identified in the QA audit beyond the original test_pipeline.py.

Author  : Aditi (QA, Testing, Data, DevOps)
Covers  : risk scoring, RAG, summarizer, MTTT metrics, ML fallback,
          schema validation, output files, cross-asset scoring, failure modes.

Run:
    python -m unittest discover -s tests -v
"""

import csv
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

# Ensure project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_alert(alert_id, asset_id, alert_type, src_ip, dst_ip,
                severity, fp_rate, technique_id, tactic, ts="2026-09-26T08:00:00"):
    return {
        "alert_id": alert_id,
        "timestamp": ts,
        "asset_id": asset_id,
        "alert_type": alert_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "technique_id": technique_id,
        "technique_name": "Test Technique",
        "tactic": tactic,
        "base_severity": severity,
        "false_positive_rate": fp_rate,
    }


def _make_incident(asset_ids, tactics, alert_count=1, severities=None, fp_rates=None):
    """Produce a minimal incident dict suitable for scoring."""
    if severities is None:
        severities = [5] * alert_count
    if fp_rates is None:
        fp_rates = [0.3] * alert_count

    alerts = [
        _make_alert(
            f"A-{i:05d}", asset_ids[0], "lsass_access",
            "10.0.0.1", "10.0.0.2", severities[i], fp_rates[i],
            "T1003.001", tactics[0] if tactics else "Credential Access",
        )
        for i in range(alert_count)
    ]

    return {
        "incident_id": f"INC-TEST-{asset_ids[0]}",
        "asset_id": asset_ids[0],
        "assets": asset_ids,
        "alert_ids": [a["alert_id"] for a in alerts],
        "alert_count": len(alerts),
        "start_time": "2026-09-26T08:00:00",
        "end_time": "2026-09-26T08:19:00",
        "techniques": ["T1003.001"],
        "tactics": tactics,
        "correlation_method": "entity_graph",
        "alerts": alerts,
    }


# ──────────────────────────────────────────────────────────────────────────────
# 1. Risk Tier Boundary Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskTierBoundaries(unittest.TestCase):
    """Verify that risk_tier() maps scores to the correct tiers at every boundary."""

    def setUp(self):
        from scoring import risk_tier
        self.risk_tier = risk_tier

    def _max_possible(self):
        # 10 * 10 * 1.0 * 1.5 * 1.3 = 195
        return 10 * 10 * 1.0 * 1.5 * 1.3

    def test_critical_tier(self):
        max_p = self._max_possible()
        self.assertEqual(self.risk_tier(max_p * 0.45), "CRITICAL")
        self.assertEqual(self.risk_tier(max_p * 0.99), "CRITICAL")

    def test_high_tier(self):
        max_p = self._max_possible()
        self.assertEqual(self.risk_tier(max_p * 0.25), "HIGH")
        self.assertEqual(self.risk_tier(max_p * 0.44), "HIGH")

    def test_medium_tier(self):
        max_p = self._max_possible()
        self.assertEqual(self.risk_tier(max_p * 0.10), "MEDIUM")
        self.assertEqual(self.risk_tier(max_p * 0.24), "MEDIUM")

    def test_low_tier(self):
        max_p = self._max_possible()
        self.assertEqual(self.risk_tier(max_p * 0.00), "LOW")
        self.assertEqual(self.risk_tier(max_p * 0.09), "LOW")


# ──────────────────────────────────────────────────────────────────────────────
# 2. Score Incident Formula Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestScoreIncident(unittest.TestCase):
    """Verify score_incident() respects the multi-factor formula."""

    def setUp(self):
        from scoring import score_incident
        self.score_incident = score_incident

    def test_critical_asset_scores_higher_than_low_asset_same_severity(self):
        """DC01 (CRITICAL) must outscore KIOSK-LOBBY (LOW) with identical alerts."""
        inc_crit = _make_incident(["DC01"], ["Credential Access"],
                                  alert_count=1, severities=[5], fp_rates=[0.2])
        inc_low  = _make_incident(["KIOSK-LOBBY"], ["Credential Access"],
                                  alert_count=1, severities=[5], fp_rates=[0.2])
        s_crit = self.score_incident(inc_crit)["risk_score"]
        s_low  = self.score_incident(inc_low)["risk_score"]
        self.assertGreater(s_crit, s_low,
                           "CRITICAL asset should score higher than LOW asset")

    def test_multi_stage_chain_scores_higher_than_single_tactic(self):
        """3 tactics should get 1.5× bonus; 1 tactic gets 1.0×."""
        inc_multi = _make_incident(
            ["DC01"],
            ["Initial Access", "Credential Access", "Impact"],
            alert_count=3,
        )
        inc_single = _make_incident(
            ["DC01"],
            ["Credential Access"],
            alert_count=1,
        )
        s_multi  = self.score_incident(inc_multi)["risk_score"]
        s_single = self.score_incident(inc_single)["risk_score"]
        self.assertGreater(s_multi, s_single)

    def test_cross_asset_uses_max_criticality(self):
        """A cross-asset incident including DC01 must use weight=10, not KIOSK weight=1."""
        inc_cross = _make_incident(
            ["KIOSK-LOBBY", "DC01"],
            ["Credential Access"],
            alert_count=2,
        )
        scored = self.score_incident(inc_cross)
        # DC01 weight=10 must have been chosen
        self.assertEqual(scored["asset_criticality_weight"], 10)

    def test_volume_factor_is_capped_at_1_3(self):
        """Even 200 alerts should not push volume_factor above 1.3."""
        inc_noisy = _make_incident(
            ["PRINT-SRV01"], ["Credential Access"],
            alert_count=200,
            severities=[1] * 200,
            fp_rates=[0.9] * 200,
        )
        scored = self.score_incident(inc_noisy)
        # max volume_factor = 1.3; single-tactic chain_bonus = 1.0; sev=1; weight=1
        self.assertLessEqual(scored["risk_score"], 1 * 1 * 1.0 * 1.0 * 1.3 * 1.01)

    def test_score_contains_required_keys(self):
        inc = _make_incident(["DC01"], ["Credential Access"])
        scored = self.score_incident(inc)
        for key in ("risk_score", "confidence", "chain_bonus", "asset_criticality_weight",
                    "predicted_next_stage", "ml_confidence"):
            self.assertIn(key, scored, f"Missing key: {key}")

    def test_high_severity_scores_above_low_severity(self):
        inc_hi = _make_incident(["DC01"], ["Credential Access"],
                                alert_count=1, severities=[10], fp_rates=[0.05])
        inc_lo = _make_incident(["DC01"], ["Credential Access"],
                                alert_count=1, severities=[1], fp_rates=[0.9])
        s_hi = self.score_incident(inc_hi)["risk_score"]
        s_lo = self.score_incident(inc_lo)["risk_score"]
        self.assertGreater(s_hi, s_lo)


# ──────────────────────────────────────────────────────────────────────────────
# 3. RAG Retrieval Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRAGRetrieval(unittest.TestCase):
    """Verify the local ATT&CK retrieval layer is robust."""

    def setUp(self):
        from rag import retrieve, context_for_incident
        self.retrieve = retrieve
        self.context_for_incident = context_for_incident

    def test_known_technique_returns_relevant_doc(self):
        results = self.retrieve("T1003.001 LSASS Credential Access", k=3)
        self.assertGreater(len(results), 0)
        joined = " ".join(results)
        self.assertTrue(
            "LSASS" in joined or "credential" in joined.lower(),
            "Expected LSASS-related context in results"
        )

    def test_unknown_query_still_returns_at_least_one_doc(self):
        """RAG must never return an empty list, even for garbage input."""
        results = self.retrieve("xyzzy gibberish abc999", k=3)
        self.assertGreaterEqual(len(results), 1,
                                "RAG should return at least 1 fallback document")

    def test_empty_incident_returns_at_least_one_doc(self):
        results = self.context_for_incident({"techniques": [], "tactics": []}, k=3)
        self.assertGreaterEqual(len(results), 1)

    def test_context_for_incident_uses_techniques(self):
        incident = {"techniques": ["T1486"], "tactics": ["Impact"]}
        results = self.context_for_incident(incident, k=2)
        self.assertGreater(len(results), 0)
        joined = " ".join(results)
        self.assertIn("T1486", joined)


# ──────────────────────────────────────────────────────────────────────────────
# 4. Summarizer Offline Mode Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestSummarizerOffline(unittest.TestCase):
    """Verify the deterministic template brief works with no external services."""

    def setUp(self):
        import os
        os.environ.pop("ANTHROPIC_API_KEY", None)
        os.environ.pop("OLLAMA_MODEL", None)
        # Force reimport with cleared env
        for mod in list(sys.modules.keys()):
            if "summarizer" in mod:
                del sys.modules[mod]
        from scoring import score_incident, risk_tier
        inc_raw = _make_incident(["DC01"], ["Credential Access", "Impact"],
                                 alert_count=2, severities=[9, 10], fp_rates=[0.2, 0.05])
        scored = score_incident(inc_raw)
        scored["risk_tier"] = risk_tier(scored["risk_score"])
        self.incident = scored

    def test_brief_is_not_empty(self):
        from summarizer import generate_brief
        brief = generate_brief(self.incident)
        self.assertGreater(len(brief), 100,
                           "Brief should be substantive, not empty or truncated")

    def test_brief_contains_mitre_technique(self):
        from summarizer import generate_brief
        brief = generate_brief(self.incident)
        self.assertIn("T1003.001", brief, "Brief must cite the MITRE technique ID")

    def test_brief_contains_attack_timeline(self):
        from summarizer import generate_brief
        brief = generate_brief(self.incident)
        # Timeline is written as "Attack timeline: HH:MM [...] -> ..."
        self.assertIn("timeline", brief.lower(),
                      "Brief should include an attack timeline")

    def test_brief_contains_recommendation(self):
        from summarizer import generate_brief
        brief = generate_brief(self.incident)
        self.assertIn("Recommended action", brief,
                      "Brief must include a recommended action")

    def test_brief_contains_risk_tier(self):
        from summarizer import generate_brief
        brief = generate_brief(self.incident)
        tier = self.incident["risk_tier"]
        self.assertIn(tier, brief,
                      f"Brief must mention the risk tier ({tier})")


# ──────────────────────────────────────────────────────────────────────────────
# 5. MTTT Metrics Calculation Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestMTTTMetrics(unittest.TestCase):
    """Verify MTTT formulas produce expected numerical results."""

    def setUp(self):
        from metrics import baseline_mttt_minutes, pipeline_mttt_minutes, summarize_metrics
        self.baseline = baseline_mttt_minutes
        self.pipeline = pipeline_mttt_minutes
        self.summarize = summarize_metrics

    def test_ransomware_baseline_is_10_min_per_alert(self):
        alerts = [{"alert_type": "ransomware_note_created"}] * 5
        total, per_alert = self.baseline(alerts)
        self.assertEqual(total, 50)       # 10 min × 5
        self.assertEqual(per_alert, 10.0)

    def test_unknown_alert_type_defaults_to_4_min(self):
        alerts = [{"alert_type": "totally_unknown_type"}]
        total, per_alert = self.baseline(alerts)
        self.assertEqual(total, 4)
        self.assertEqual(per_alert, 4.0)

    def test_pipeline_critical_incident_costs_12_min(self):
        incidents = [{"risk_tier": "CRITICAL", "alert_count": 1}]
        total, per_alert, covered = self.pipeline(incidents)
        self.assertAlmostEqual(total, 12.25, places=1)  # 12 + 0.25 overhead

    def test_pipeline_always_fewer_minutes_than_baseline(self):
        from alert_generator import generate_alerts
        from grouping import group_alerts_into_incidents
        from scoring import score_and_rank, risk_tier
        alerts = generate_alerts(500, 2, seed=42)
        clusters = group_alerts_into_incidents(alerts)
        scored = score_and_rank(clusters)
        for inc in scored:
            inc["risk_tier"] = risk_tier(inc["risk_score"])
        metrics = self.summarize(alerts, scored)
        self.assertLess(
            metrics["pipeline_total_minutes"],
            metrics["baseline_total_minutes"],
            "Pipeline must always reduce total analyst minutes"
        )

    def test_noise_reduction_is_positive(self):
        from alert_generator import generate_alerts
        from grouping import group_alerts_into_incidents
        from scoring import score_and_rank, risk_tier
        alerts = generate_alerts(200, 2, seed=42)
        clusters = group_alerts_into_incidents(alerts)
        scored = score_and_rank(clusters)
        for inc in scored:
            inc["risk_tier"] = risk_tier(inc["risk_score"])
        metrics = self.summarize(alerts, scored)
        self.assertGreater(metrics["noise_reduction_ratio"], 1.0)
        self.assertLess(metrics["n_incidents"], metrics["n_alerts"])


# ──────────────────────────────────────────────────────────────────────────────
# 6. ML Model Fallback Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestMLModelFallback(unittest.TestCase):
    """Verify the pipeline degrades gracefully when the model file is missing."""

    def test_is_available_false_when_model_missing(self):
        model_path = os.path.join(os.path.dirname(__file__), "..", "severity_model.pkl")
        backup_path = model_path + ".bak"
        shutil.move(model_path, backup_path)
        try:
            # Force re-import to pick up missing file
            for mod in list(sys.modules.keys()):
                if "ml_classifier" in mod:
                    del sys.modules[mod]
            from ml_classifier import is_available
            self.assertFalse(is_available())
        finally:
            shutil.move(backup_path, model_path)

    def test_pipeline_runs_without_model(self):
        """
        Verify the pipeline produces valid output regardless of ML model availability.
        Note: _USE_ML in scoring.py is evaluated once at import time. Within a single
        test process, the flag cannot be reset by clearing sys.modules. This test
        therefore validates structural correctness — the pipeline always runs and
        produces non-zero confidence scores whether ML is on or off.
        """
        from pipeline import run_pipeline
        result = run_pipeline(50, 1, seed=7)
        self.assertEqual(result["metrics"]["n_alerts"], 50)
        self.assertGreater(len(result["incidents"]), 0)
        # Confidence must always be positive (either ML-boosted or static FP prior)
        for inc in result["incidents"]:
            self.assertGreater(inc["confidence"], 0.0,
                               f"Incident {inc['incident_id']} has zero confidence")
        # ml_confidence is a bool flag (True = ML used, False = static)
        # Both values are valid; we assert the key always exists
        for inc in result["incidents"]:
            self.assertIn("ml_confidence", inc,
                          "ml_confidence key must be present in every incident")


# ──────────────────────────────────────────────────────────────────────────────
# 7. Human Loop Failure Mode Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestHumanLoopFailureModes(unittest.TestCase):
    """Verify that invalid inputs to human_loop raise explicit errors."""

    def setUp(self):
        from human_loop import apply_disposition, build_review_queue
        self.apply_disposition = apply_disposition
        self.build_review_queue = build_review_queue
        self.queue = [
            {"incident_id": "INC-TEST-1",
             "risk_tier": "LOW",
             "risk_score": 2.5,
             "asset_id": "KIOSK-LOBBY"}
        ]

    def test_invalid_disposition_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            self.apply_disposition(self.queue, "INC-TEST-1", "DESTROY_ALL", "tester")
        self.assertIn("Invalid disposition", str(ctx.exception))

    def test_unknown_incident_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            self.apply_disposition(self.queue, "INC-DOES-NOT-EXIST", "TRUE_POSITIVE", "tester")

    def test_valid_disposition_updates_queue(self):
        import os
        os.environ["FEEDBACK_LOG_PATH"] = os.path.join(
            tempfile.gettempdir(), "test_feedback_log.csv"
        )
        try:
            self.apply_disposition(self.queue, "INC-TEST-1", "FALSE_POSITIVE", "tester", "known-benign")
            self.assertEqual(self.queue[0]["disposition"], "FALSE_POSITIVE")
            self.assertEqual(self.queue[0]["reviewed_by"], "tester")
        finally:
            path = os.environ.pop("FEEDBACK_LOG_PATH", None)
            if path and os.path.exists(path):
                os.remove(path)

    def test_all_incidents_start_as_pending(self):
        from scoring import score_incident, risk_tier
        from grouping import group_alerts_into_incidents
        from alert_generator import generate_alerts
        from scoring import score_and_rank
        alerts = generate_alerts(50, 1, seed=9)
        clusters = group_alerts_into_incidents(alerts)
        scored = score_and_rank(clusters)
        for inc in scored:
            inc["risk_tier"] = risk_tier(inc["risk_score"])
        queue = self.build_review_queue(scored)
        for item in queue:
            self.assertEqual(item["disposition"], "PENDING",
                             f"Incident {item['incident_id']} should start as PENDING")


# ──────────────────────────────────────────────────────────────────────────────
# 8. Output File Existence and Schema Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestOutputFilesAndSchema(unittest.TestCase):
    """Verify main.py creates all expected output files with correct schema."""

    OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")

    REQUIRED_FILES = [
        "alerts.csv",
        "incidents.json",
        "review_queue.csv",
        "shift_brief.md",
        "mttt_metrics.md",
        "metrics.json",
    ]

    REQUIRED_ALERT_FIELDS = {
        "alert_id", "timestamp", "asset_id", "alert_type",
        "src_ip", "dst_ip", "technique_id", "technique_name",
        "tactic", "base_severity", "false_positive_rate",
    }

    def test_all_output_files_exist(self):
        for fname in self.REQUIRED_FILES:
            path = os.path.join(self.OUTPUTS_DIR, fname)
            self.assertTrue(os.path.exists(path), f"Missing output file: {fname}")

    def test_alerts_csv_has_correct_schema(self):
        path = os.path.join(self.OUTPUTS_DIR, "alerts.csv")
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            fields = set(reader.fieldnames)
            missing = self.REQUIRED_ALERT_FIELDS - fields
            self.assertEqual(missing, set(), f"alerts.csv missing fields: {missing}")
            rows = list(reader)
        self.assertEqual(len(rows), 3000, "alerts.csv should have 3000 alert rows")

    def test_incidents_json_has_correct_schema(self):
        path = os.path.join(self.OUTPUTS_DIR, "incidents.json")
        with open(path) as f:
            incidents = json.load(f)
        self.assertGreater(len(incidents), 0)
        required = {"incident_id", "risk_tier", "risk_score", "asset_id",
                    "alert_count", "techniques", "tactics", "confidence", "brief"}
        for inc in incidents:
            missing = required - set(inc.keys())
            self.assertEqual(missing, set(),
                             f"Incident {inc.get('incident_id')} missing keys: {missing}")

    def test_no_incident_has_empty_brief(self):
        path = os.path.join(self.OUTPUTS_DIR, "incidents.json")
        with open(path) as f:
            incidents = json.load(f)
        empty_briefs = [i["incident_id"] for i in incidents if not i.get("brief")]
        self.assertEqual(empty_briefs, [],
                         f"Incidents with empty briefs: {empty_briefs}")

    def test_metrics_json_is_internally_consistent(self):
        metrics_path = os.path.join(self.OUTPUTS_DIR, "metrics.json")
        alerts_path  = os.path.join(self.OUTPUTS_DIR, "alerts.csv")
        inc_path     = os.path.join(self.OUTPUTS_DIR, "incidents.json")
        queue_path   = os.path.join(self.OUTPUTS_DIR, "review_queue.csv")

        with open(metrics_path) as f:
            metrics = json.load(f)
        with open(alerts_path, newline="") as f:
            n_alerts = sum(1 for _ in csv.DictReader(f))
        with open(inc_path) as f:
            n_incidents = len(json.load(f))
        with open(queue_path, newline="") as f:
            n_queue = sum(1 for _ in csv.DictReader(f))

        self.assertEqual(metrics["n_alerts"], n_alerts,
                         "metrics.json n_alerts must match alerts.csv row count")
        self.assertEqual(metrics["n_incidents"], n_incidents,
                         "metrics.json n_incidents must match incidents.json length")
        self.assertEqual(n_incidents, n_queue,
                         "review_queue.csv must have one row per incident")

    def test_metrics_reduction_is_positive(self):
        path = os.path.join(self.OUTPUTS_DIR, "metrics.json")
        with open(path) as f:
            metrics = json.load(f)
        self.assertGreater(metrics["mttt_reduction_pct_per_alert"], 0)
        self.assertGreater(metrics["analyst_time_reduction_pct"], 0)
        self.assertGreater(metrics["noise_reduction_ratio"], 1.0)

    def test_review_queue_all_start_pending(self):
        path = os.path.join(self.OUTPUTS_DIR, "review_queue.csv")
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        non_pending = [r["incident_id"] for r in rows if r["disposition"] != "PENDING"]
        self.assertEqual(non_pending, [],
                         f"These incidents are not PENDING after a fresh run: {non_pending}")


# ──────────────────────────────────────────────────────────────────────────────
# 9. Pipeline Performance / Timing Test
# ──────────────────────────────────────────────────────────────────────────────

class TestPipelinePerformance(unittest.TestCase):
    """Verify the pipeline completes within a reasonable time SLO."""

    def test_3000_alert_pipeline_completes_in_under_30_seconds(self):
        from pipeline import run_pipeline
        start = time.time()
        result = run_pipeline(3000, 6, seed=42)
        elapsed = time.time() - start
        self.assertLess(elapsed, 30,
                        f"Pipeline took {elapsed:.1f}s — must complete in < 30s")
        self.assertEqual(result["metrics"]["n_alerts"], 3000)


# ──────────────────────────────────────────────────────────────────────────────
# 10. Reproducibility Test (cross-module)
# ──────────────────────────────────────────────────────────────────────────────

class TestReproducibility(unittest.TestCase):
    """Two runs with the same seed must produce bit-for-bit identical results."""

    def test_full_pipeline_is_deterministic(self):
        from pipeline import run_pipeline
        r1 = run_pipeline(200, 2, seed=42)
        r2 = run_pipeline(200, 2, seed=42)

        ids1 = [a["alert_id"] for a in r1["alerts"]]
        ids2 = [a["alert_id"] for a in r2["alerts"]]
        self.assertEqual(ids1, ids2, "Alert IDs differ between runs with same seed")

        scores1 = [round(i["risk_score"], 4) for i in r1["incidents"]]
        scores2 = [round(i["risk_score"], 4) for i in r2["incidents"]]
        self.assertEqual(scores1, scores2, "Risk scores differ between runs with same seed")

        self.assertEqual(r1["metrics"], r2["metrics"],
                         "Metrics differ between runs with same seed")

    def test_different_seeds_produce_different_outputs(self):
        from pipeline import run_pipeline
        r42 = run_pipeline(200, 2, seed=42)
        r99 = run_pipeline(200, 2, seed=99)
        ids42 = [a["alert_id"] for a in r42["alerts"]]
        ids99 = [a["alert_id"] for a in r99["alerts"]]
        # Seeds 42 and 99 must produce different sequences
        self.assertNotEqual(ids42, ids99,
                            "Different seeds produced identical alert sequences")


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main()
