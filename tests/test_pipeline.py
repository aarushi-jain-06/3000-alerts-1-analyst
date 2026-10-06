import unittest

from alert_generator import generate_alerts
from grouping import group_alerts_into_incidents, group_by_asset_time
from human_loop import apply_disposition, merge_incidents
from pipeline import run_pipeline


class PipelineTests(unittest.TestCase):
    def test_generation_is_reproducible(self):
        self.assertEqual(generate_alerts(30, 1, seed=7), generate_alerts(30, 1, seed=7))

    def test_graph_catches_cross_asset_connection(self):
        alerts = [
            {"alert_id": "1", "timestamp": "2026-09-26T00:00:00", "asset_id": "ENG-LAPTOP-114", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "alert_type": "port_scan_detected", "technique_id": "T1046", "tactic": "Discovery", "base_severity": 4, "false_positive_rate": .7},
            {"alert_id": "2", "timestamp": "2026-09-26T00:05:00", "asset_id": "DC01", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "alert_type": "lsass_access", "technique_id": "T1003.001", "tactic": "Credential Access", "base_severity": 9, "false_positive_rate": .2},
        ]
        incidents = group_alerts_into_incidents(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(set(incidents[0]["assets"]), {"ENG-LAPTOP-114", "DC01"})

    def test_fallback_grouping_remains_available(self):
        self.assertIsInstance(group_by_asset_time([]), list)

    def test_pipeline_has_investigation_and_metrics(self):
        result = run_pipeline(100, 1, seed=3)
        self.assertEqual(result["metrics"]["n_alerts"], 100)
        self.assertTrue(all("brief" in incident for incident in result["incidents"]))

    def test_merge_rescores(self):
        result = run_pipeline(40, 1, seed=4)
        merged = merge_incidents(result["incidents"][0], result["incidents"][1])
        self.assertEqual(merged["alert_count"], result["incidents"][0]["alert_count"] + result["incidents"][1]["alert_count"])
        self.assertIn(merged["risk_tier"], {"CRITICAL", "HIGH", "MEDIUM", "LOW"})

    def test_disposition_is_applied(self):
        queue = [{"incident_id": "INC-1", "risk_tier": "LOW", "risk_score": 1, "asset_id": "KIOSK-LOBBY"}]
        apply_disposition(queue, "INC-1", "FALSE_POSITIVE", "tester", "known benign")
        self.assertEqual(queue[0]["disposition"], "FALSE_POSITIVE")


if __name__ == "__main__":
    unittest.main()
