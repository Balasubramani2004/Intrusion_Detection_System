#!/usr/bin/env python3
"""
Verify LAN port-scan detection (same as teammate nmap -sS on your Wi-Fi IP).

Run from project root with venv:
  .venv/bin/python scripts/verify_lan_scan_detection.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from capture.scan_detector import ScanTracker, ArpScanTracker
from config import (
    SCAN_BURST_MIN_PORTS,
    SCAN_BURST_WINDOW_SEC,
    SCAN_LOCAL_BURST_MIN_PORTS,
    LAN_ARP_MIN_HOSTS,
)


def test_tcp_lan_scan():
    tracker = ScanTracker(
        local_ips={"192.168.1.100"},
        local_burst_min_ports=SCAN_LOCAL_BURST_MIN_PORTS,
        burst_min_ports=SCAN_BURST_MIN_PORTS,
        burst_window_sec=SCAN_BURST_WINDOW_SEC,
        exclude_ports={80, 443, 53},
    )
    scanner, victim = "192.168.1.55", "192.168.1.100"
    for port in range(3000, 3000 + SCAN_LOCAL_BURST_MIN_PORTS + 2):
        tracker.record_packet_syn(scanner, victim, port)
    hit = tracker.evaluate(scanner)
    assert hit["suspected"], f"Expected scan detect, got {hit}"
    assert hit["scanner_ip"] == scanner or hit.get("dst_ip") == victim
    assert "LAN scan" in hit.get("scan_evidence", "")
    print("OK  TCP LAN scan (scanner -> your PC):", hit["scan_evidence"])
    return hit


def test_tcp_lan_scan_third_party():
    tracker = ScanTracker(
        burst_min_ports=SCAN_BURST_MIN_PORTS,
        burst_window_sec=SCAN_BURST_WINDOW_SEC,
        exclude_ports={80, 443, 53},
    )
    scanner, victim = "192.168.1.44", "192.168.1.200"
    for port in range(4000, 4000 + SCAN_BURST_MIN_PORTS + 2):
        tracker.record_packet_syn(scanner, victim, port)
    hits = tracker.evaluate_all()
    assert hits, "Expected scan between two LAN hosts"
    print("OK  TCP LAN scan (A -> B):", hits[0]["scan_evidence"])
    return hits[0]


def test_arp_sweep():
    arp = ArpScanTracker(min_unique_hosts=LAN_ARP_MIN_HOSTS)
    scanner = "192.168.1.60"
    for i in range(1, LAN_ARP_MIN_HOSTS + 2):
        arp.record_who_has(scanner, f"192.168.1.{i}")
    ev = arp.evaluate(scanner)
    assert ev["suspected"], ev
    print("OK  ARP sweep:", ev["scan_evidence"])
    return ev


def main():
    print("LAN scan detection verification")
    print(f"  burst: {SCAN_BURST_MIN_PORTS} ports / {SCAN_BURST_WINDOW_SEC}s")
    print(f"  local victim: {SCAN_LOCAL_BURST_MIN_PORTS} ports")
    print()
    test_tcp_lan_scan()
    test_tcp_lan_scan_third_party()
    test_arp_sweep()
    print()
    print("All checks passed. Live test: nmap -sS <your-wifi-ip> from another device.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
