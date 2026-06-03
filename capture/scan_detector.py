"""
LAN port-scan / nmap detection for Wi-Fi capture.

Detects when any host on the visible network scans another host:
  scanner_ip -> many TCP SYN probes -> victim_ip (many ports).

Also supports ARP host-discovery sweeps (nmap -sn / arp-scan).
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from statistics import median
from typing import Any, Dict, List, Optional, Set, Tuple

from capture.network_utils import is_private_lan_ip


@dataclass
class _ScanEvent:
    ts: float
    dst_ip: str
    dst_port: int
    is_syn: bool
    pkt_count: int = 1
    duration: float = 0.0


class ScanTracker:
    """Sliding-window tracker: one scanner IP probing many ports on a victim IP."""

    def __init__(
        self,
        window_sec: float = 30.0,
        min_unique_ports: int = 12,
        min_syn_events: int = 10,
        heuristic_threshold: float = 0.80,
        cooldown_sec: float = 45.0,
        burst_window_sec: float = 12.0,
        burst_min_ports: int = 8,
        burst_min_syn_events: int = 8,
        exclude_ports: Optional[set] = None,
        local_ips: Optional[Set[str]] = None,
        local_burst_min_ports: int = 6,
        lan_subnet_only: bool = True,
    ):
        self.window_sec = window_sec
        self.min_unique_ports = min_unique_ports
        self.min_syn_events = min_syn_events
        self.heuristic_threshold = heuristic_threshold
        self.cooldown_sec = cooldown_sec
        self.burst_window_sec = burst_window_sec
        self.burst_min_ports = burst_min_ports
        self.burst_min_syn_events = burst_min_syn_events
        self.exclude_ports = exclude_ports or set()
        self.local_ips: Set[str] = set(local_ips or [])
        self.local_burst_min_ports = local_burst_min_ports
        self.lan_subnet_only = lan_subnet_only
        self._events: Dict[str, List[_ScanEvent]] = defaultdict(list)
        self._last_alert: Dict[Tuple[str, str], float] = {}

    def set_local_ips(self, ips: Set[str]) -> None:
        self.local_ips = set(ips or [])

    def _prune(self, src_ip: str, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        cutoff = now - self.window_sec
        self._events[src_ip] = [e for e in self._events[src_ip] if e.ts >= cutoff]
        if not self._events[src_ip]:
            self._events.pop(src_ip, None)

    def _lan_ok(self, ip: str) -> bool:
        if not self.lan_subnet_only:
            return True
        return is_private_lan_ip(ip)

    def record_flow(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        *,
        is_syn: bool = False,
        pkt_count: int = 1,
        duration: float = 0.0,
    ) -> None:
        if not src_ip or not dst_ip:
            return
        if not self._lan_ok(src_ip) or not self._lan_ok(dst_ip):
            return
        if src_ip == dst_ip:
            return
        if not self._count_port(int(dst_port or 0)):
            return
        now = time.time()
        self._prune(src_ip, now)
        self._events[src_ip].append(
            _ScanEvent(
                ts=now,
                dst_ip=dst_ip,
                dst_port=int(dst_port or 0),
                is_syn=is_syn,
                pkt_count=max(1, int(pkt_count)),
                duration=float(duration or 0.0),
            )
        )

    def _count_port(self, port: int) -> bool:
        return bool(port) and port not in self.exclude_ports

    def record_packet_syn(self, src_ip: str, dst_ip: str, dst_port: int) -> None:
        if not self._count_port(int(dst_port or 0)):
            return
        self.record_flow(
            src_ip, dst_ip, dst_port, is_syn=True, pkt_count=1, duration=0.0
        )

    def can_alert(self, scanner_ip: str, victim_ip: str) -> bool:
        key = (scanner_ip, victim_ip)
        last = self._last_alert.get(key, 0.0)
        return (time.time() - last) >= self.cooldown_sec

    def mark_alert(self, scanner_ip: str, victim_ip: str) -> None:
        self._last_alert[(scanner_ip, victim_ip)] = time.time()

    def _burst_thresholds(self, victim_ip: str) -> Tuple[int, int]:
        if victim_ip in self.local_ips:
            return self.local_burst_min_ports, max(5, self.burst_min_syn_events - 2)
        return self.burst_min_ports, self.burst_min_syn_events

    def _score_pair(
        self,
        scanner_ip: str,
        victim_ip: str,
        evs: List[_ScanEvent],
        now: float,
    ) -> Optional[Dict[str, Any]]:
        burst_cutoff = now - self.burst_window_sec
        burst_evs = [e for e in evs if e.ts >= burst_cutoff]
        burst_ports_req, burst_syn_req = self._burst_thresholds(victim_ip)

        if burst_evs:
            burst_ports = {
                e.dst_port for e in burst_evs
                if self._count_port(e.dst_port)
            }
            burst_syn = sum(1 for e in burst_evs if e.is_syn)
            if (
                len(burst_ports) >= burst_ports_req
                and burst_syn >= burst_syn_req
                and burst_syn >= len(burst_evs) * 0.7
            ):
                span = max(e.ts for e in burst_evs) - min(e.ts for e in burst_evs)
                span_int = max(1, int(span))
                victim_tag = "this device" if victim_ip in self.local_ips else victim_ip
                evidence = (
                    f"LAN scan: {scanner_ip} probed {len(burst_ports)} ports on "
                    f"{victim_tag} in {span_int}s"
                )
                return {
                    "suspected": True,
                    "score": 0.93,
                    "reason": evidence,
                    "scanner_ip": scanner_ip,
                    "dst_ip": victim_ip,
                    "unique_ports": len(burst_ports),
                    "syn_events": burst_syn,
                    "window_sec": self.burst_window_sec,
                    "scan_evidence": evidence,
                    "detection_mode": "lan_burst",
                    "victim_is_local": victim_ip in self.local_ips,
                }

        ports = {e.dst_port for e in evs if self._count_port(e.dst_port)}
        unique_ports = len(ports)
        syn_events = sum(1 for e in evs if e.is_syn)
        min_ports = self.min_unique_ports
        min_syn = self.min_syn_events
        if victim_ip in self.local_ips:
            min_ports = max(self.local_burst_min_ports, min_ports - 4)
            min_syn = max(5, min_syn - 3)

        if unique_ports < min_ports and syn_events < min_syn:
            return None

        port_ratio = unique_ports / max(min_ports, 1)
        syn_ratio = syn_events / max(min_syn, 1)
        score = max(min(1.0, port_ratio), min(1.0, syn_ratio))

        durations = [e.duration for e in evs if e.duration > 0]
        if durations and median(durations) < 2.0 and syn_events >= 3:
            score = min(1.0, score + 0.1)

        if score < self.heuristic_threshold:
            return None

        span = max(e.ts for e in evs) - min(e.ts for e in evs) if len(evs) > 1 else 0.0
        span_int = max(1, int(span))
        victim_tag = "this device" if victim_ip in self.local_ips else victim_ip
        evidence = (
            f"LAN scan: {scanner_ip} probed {unique_ports} ports on "
            f"{victim_tag} in {span_int}s"
        )
        return {
            "suspected": True,
            "score": round(score, 4),
            "reason": evidence,
            "scanner_ip": scanner_ip,
            "dst_ip": victim_ip,
            "unique_ports": unique_ports,
            "syn_events": syn_events,
            "window_sec": self.window_sec,
            "scan_evidence": evidence,
            "detection_mode": "lan_window",
            "victim_is_local": victim_ip in self.local_ips,
        }

    def evaluate(self, scanner_ip: str) -> Dict[str, Any]:
        """Best scan hypothesis for one scanner IP."""
        hits = self.evaluate_all(scanner_ip=scanner_ip)
        if hits:
            return hits[0]
        return self._empty_result()

    def evaluate_all(self, scanner_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """All active LAN scan alerts (optionally for one scanner only)."""
        now = time.time()
        scanners = [scanner_ip] if scanner_ip else list(self._events.keys())
        results: List[Dict[str, Any]] = []

        for src in scanners:
            if not src:
                continue
            self._prune(src, now)
            events = self._events.get(src, [])
            if not events:
                continue
            by_dst: Dict[str, List[_ScanEvent]] = defaultdict(list)
            for ev in events:
                by_dst[ev.dst_ip].append(ev)

            for victim_ip, evs in by_dst.items():
                candidate = self._score_pair(src, victim_ip, evs, now)
                if candidate:
                    results.append(candidate)

        results.sort(key=lambda r: (r.get("victim_is_local", False), r.get("score", 0)), reverse=True)
        return results

    def _empty_result(self) -> Dict[str, Any]:
        return {
            "suspected": False,
            "score": 0.0,
            "reason": "",
            "scanner_ip": "",
            "dst_ip": "",
            "unique_ports": 0,
            "syn_events": 0,
            "window_sec": self.window_sec,
            "scan_evidence": "",
            "detection_mode": "",
            "victim_is_local": False,
        }


@dataclass
class _ArpProbe:
    ts: float
    target_ip: str


class ArpScanTracker:
    """Detect ARP host-discovery sweeps on the LAN (nmap -sn, arp-scan)."""

    def __init__(
        self,
        window_sec: float = 25.0,
        min_unique_hosts: int = 8,
        cooldown_sec: float = 60.0,
    ):
        self.window_sec = window_sec
        self.min_unique_hosts = min_unique_hosts
        self.cooldown_sec = cooldown_sec
        self._events: Dict[str, List[_ArpProbe]] = defaultdict(list)
        self._last_alert: Dict[str, float] = {}

    def record_who_has(self, requester_ip: str, target_ip: str) -> None:
        if not requester_ip or not target_ip:
            return
        if not is_private_lan_ip(requester_ip) or not is_private_lan_ip(target_ip):
            return
        if requester_ip == target_ip:
            return
        now = time.time()
        cutoff = now - self.window_sec
        self._events[requester_ip] = [
            e for e in self._events[requester_ip] if e.ts >= cutoff
        ]
        self._events[requester_ip].append(_ArpProbe(ts=now, target_ip=target_ip))

    def can_alert(self, requester_ip: str) -> bool:
        last = self._last_alert.get(requester_ip, 0.0)
        return (time.time() - last) >= self.cooldown_sec

    def mark_alert(self, requester_ip: str) -> None:
        self._last_alert[requester_ip] = time.time()

    def evaluate(self, requester_ip: str) -> Dict[str, Any]:
        empty = {
            "suspected": False,
            "scanner_ip": requester_ip,
            "scan_evidence": "",
            "score": 0.0,
        }
        now = time.time()
        cutoff = now - self.window_sec
        evs = [e for e in self._events.get(requester_ip, []) if e.ts >= cutoff]
        if not evs:
            return empty
        hosts = {e.target_ip for e in evs}
        if len(hosts) < self.min_unique_hosts:
            return empty
        span = max(e.ts for e in evs) - min(e.ts for e in evs)
        span_int = max(1, int(span))
        evidence = (
            f"LAN ARP sweep: {requester_ip} asked for {len(hosts)} hosts in {span_int}s"
        )
        return {
            "suspected": True,
            "scanner_ip": requester_ip,
            "dst_ip": "",
            "scan_evidence": evidence,
            "score": min(1.0, len(hosts) / max(self.min_unique_hosts, 1)),
            "detection_mode": "arp_sweep",
        }

    def evaluate_all(self) -> List[Dict[str, Any]]:
        return [
            self.evaluate(ip)
            for ip in list(self._events.keys())
            if self.evaluate(ip).get("suspected")
        ]
