"""Unit tests for LAN port-scan and ARP sweep detection."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.scan_detector import ScanTracker, ArpScanTracker


class TestLanScanDetector(unittest.TestCase):
    def setUp(self):
        self.tracker = ScanTracker(
            window_sec=30.0,
            min_unique_ports=10,
            min_syn_events=8,
            burst_window_sec=12.0,
            burst_min_ports=8,
            burst_min_syn_events=8,
            local_ips={"192.168.1.100"},
            local_burst_min_ports=6,
            exclude_ports={80, 443, 53},
        )

    def test_lan_scan_any_device(self):
        scanner, victim = "192.168.1.50", "192.168.1.200"
        for port in range(20, 30):
            self.tracker.record_packet_syn(scanner, victim, port)
        hits = self.tracker.evaluate_all()
        self.assertTrue(any(h["scanner_ip"] == scanner for h in hits))

    def test_scan_to_local_device_lower_threshold(self):
        scanner, victim = "192.168.1.44", "192.168.1.100"
        for port in range(3000, 3007):
            self.tracker.record_packet_syn(scanner, victim, port)
        hit = self.tracker.evaluate(scanner)
        self.assertTrue(hit["suspected"])
        self.assertTrue(hit.get("victim_is_local"))

    def test_arp_sweep(self):
        arp = ArpScanTracker(min_unique_hosts=5, window_sec=20.0)
        for i in range(1, 10):
            arp.record_who_has("192.168.1.55", f"192.168.1.{i}")
        ev = arp.evaluate("192.168.1.55")
        self.assertTrue(ev["suspected"])
        self.assertIn("ARP sweep", ev["scan_evidence"])


if __name__ == "__main__":
    unittest.main()
