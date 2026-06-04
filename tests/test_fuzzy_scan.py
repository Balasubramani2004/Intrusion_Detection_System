"""Fuzzy port-scan evaluator (optional layer; off by default in config)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.fuzzy_scan import evaluate_port_scan_fuzzy
from capture.scan_detector import ScanTracker


class TestFuzzyScanEvaluator(unittest.TestCase):
    def test_high_scan_risk_rule(self):
        out = evaluate_port_scan_fuzzy(
            unique_ports=18,
            syn_events=14,
            total_events=16,
            span_sec=4.0,
            victim_is_local=True,
            detection_mode="lan_burst",
        )
        self.assertGreaterEqual(out["score"], 0.7)
        self.assertIn("THEN", out["rule"])
        self.assertTrue(out["top_rule"])

    def test_low_background_risk(self):
        out = evaluate_port_scan_fuzzy(
            unique_ports=2,
            syn_events=1,
            total_events=5,
            span_sec=20.0,
            victim_is_local=False,
        )
        self.assertLess(out["score"], 0.5)

    def test_explain_only_does_not_change_suspected(self):
        from config import FUZZY_SCAN_ENABLED, FUZZY_SCAN_EXPLAIN_ONLY

        self.assertTrue(FUZZY_SCAN_ENABLED)
        self.assertTrue(FUZZY_SCAN_EXPLAIN_ONLY)
        tracker = ScanTracker(
            min_unique_ports=8,
            min_syn_events=6,
            burst_min_ports=6,
            burst_min_syn_events=5,
            local_ips={"192.168.1.10"},
            local_burst_min_ports=4,
            exclude_ports={80, 443},
        )
        for port in range(5000, 5010):
            tracker.record_packet_syn("10.0.0.5", "192.168.1.10", port)
        hit = tracker.evaluate("10.0.0.5")
        self.assertTrue(hit["suspected"])
        self.assertIn("fuzzy_rule", hit)
        self.assertIn("THEN", hit["fuzzy_rule"])


if __name__ == "__main__":
    unittest.main()
