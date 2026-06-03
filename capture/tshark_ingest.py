"""
FedAIDA-IDS — Windows tshark / Wireshark PCAP ingest (WSL side)

Watches a shared folder for rolling PCAP chunks written by Windows tshark
(e.g. scripts/start_wifi_tshark_windows.ps1) and feeds flows into the dashboard.

Also supports one-shot PCAP file replay via ingest_file().
"""
from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

try:
    from scapy.all import rdpcap
    from capture.live_capture import LiveCapture, SCAPY_AVAILABLE
except ImportError:
    SCAPY_AVAILABLE = False
    LiveCapture = None  # type: ignore

DEFAULT_INCOMING = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "incoming"
)
DEFAULT_PROCESSED = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "processed"
)

CHUNK_SUFFIXES = (".pcap", ".pcapng", ".cap")


class TsharkIngest:
    """
    Poll incoming/ for new PCAP chunks from Windows tshark; process via LiveCapture.
    """

    def __init__(
        self,
        on_flow_callback: Optional[Callable] = None,
        on_packet_callback: Optional[Callable] = None,
        incoming_dir: Optional[str] = None,
        processed_dir: Optional[str] = None,
        poll_interval: float = 2.0,
        stable_seconds: float = 2.0,
        min_flow_packets: int = 3,
    ):
        self.callback = on_flow_callback
        self.on_packet_callback = on_packet_callback
        self.incoming_dir = Path(incoming_dir or DEFAULT_INCOMING)
        self.processed_dir = Path(processed_dir or DEFAULT_PROCESSED)
        self.poll_interval = poll_interval
        self.stable_seconds = stable_seconds
        self.min_flow_packets = min_flow_packets
        self.running = False
        self._processed_files: set[str] = set()
        self.stats = {
            "packets": 0,
            "flows": 0,
            "chunks_processed": 0,
            "last_error": None,
            "stale_message": None,
        }
        self._capture: Optional[LiveCapture] = None
        self._pkt_index: dict[str, int] = {}
        self._last_chunk_at: float = 0.0
        self._loop_started_at: float = 0.0
        self._stale_after_seconds = 30.0
        self._partial_poll_seconds = 1.0
        self._last_partial_poll: float = 0.0

    def _ensure_dirs(self):
        self.incoming_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)

    def _list_candidates(self) -> list[Path]:
        files = []
        for pat in ("*.pcap", "*.pcapng", "*.cap"):
            files.extend(self.incoming_dir.glob(pat))
        return sorted(files, key=lambda p: p.stat().st_mtime)

    def _is_stable(self, path: Path) -> bool:
        try:
            mtime = path.stat().st_mtime
            size = path.stat().st_size
        except OSError:
            return False
        if size < 24:  # empty/tiny pcap header only
            return False
        return (time.time() - mtime) >= self.stable_seconds

    def _read_new_packets(self, path: Path, capture: LiveCapture) -> int:
        """Ingest only packets not yet read from path (supports growing PCAP files)."""
        key = str(path.resolve())
        if key in self._processed_files:
            return 0
        try:
            if path.stat().st_size < 24:
                return 0
        except OSError:
            return 0

        start_idx = self._pkt_index.get(key, 0)
        try:
            pkts = rdpcap(str(path))
        except Exception as e:
            logger.debug("rdpcap %s (may still be writing): %s", path.name, e)
            return 0

        if len(pkts) <= start_idx:
            return 0

        for pkt in pkts[start_idx:]:
            if not self.running:
                break
            capture._process_packet(pkt)

        self._pkt_index[key] = len(pkts)
        n_new = len(pkts) - start_idx
        if n_new > 0:
            self._last_chunk_at = time.time()
            self.stats["last_error"] = None
            self.stats["stale_message"] = None
            self.stats["packets"] = capture.stats.get("packets", 0)
        return n_new

    def _finalize_and_archive(self, path: Path, capture: LiveCapture) -> int:
        """Finalize flows when a PCAP chunk is complete and move to processed/."""
        key = str(path.resolve())
        if key in self._processed_files:
            return 0

        flows_before = capture.stats.get("flows", 0)
        for flow in list(capture.flows.values()):
            if flow.pkt_count >= self.min_flow_packets:
                capture._finalise_flow(flow)
            elif flow.pkt_count > 0:
                capture._finalise_flow(flow)
        capture.flows.clear()

        self._processed_files.add(key)
        self._pkt_index.pop(key, None)
        self.stats["chunks_processed"] += 1
        flows_delta = capture.stats.get("flows", 0) - flows_before
        self.stats["flows"] += max(flows_delta, 0)

        dest = self.processed_dir / path.name
        try:
            if dest.exists():
                dest = self.processed_dir / f"{path.stem}_{int(time.time())}{path.suffix}"
            try:
                path.rename(dest)
            except OSError:
                import shutil
                shutil.copy2(path, dest)
                path.unlink(missing_ok=True)
        except OSError as e:
            logger.warning("Could not move %s to processed: %s", path, e)

        return flows_delta

    def _process_chunk(self, path: Path) -> int:
        """Read one PCAP chunk end-to-end (upload / one-shot)."""
        if not SCAPY_AVAILABLE or LiveCapture is None:
            self.stats["last_error"] = "Scapy not available"
            return 0

        capture = LiveCapture(
            on_alert_callback=self._on_flow,
            on_packet_callback=self.on_packet_callback,
        )
        try:
            self._read_new_packets(path, capture)
            return self._finalize_and_archive(path, capture)
        except Exception as e:
            logger.exception("Failed to process chunk %s", path)
            self.stats["last_error"] = str(e)
            return 0

    def _on_flow(self, flow_info: dict):
        """Forward all flows; dashboard applies ML min-packet gate and scan rules."""
        if self.callback:
            self.callback(flow_info)

    def ingest_file(self, pcap_path: str) -> dict:
        """One-shot ingest of a single PCAP (upload / manual replay)."""
        path = Path(pcap_path)
        if not path.is_file():
            raise FileNotFoundError(pcap_path)
        was_running = self.running
        self.running = True
        try:
            n = self._process_chunk(path)
        finally:
            self.running = was_running
        return {"flows": n, "file": str(path)}

    def _incoming_recently_modified(self) -> bool:
        now = time.time()
        for path in self._list_candidates():
            try:
                if now - path.stat().st_mtime < 15:
                    return True
            except OSError:
                continue
        return False

    def _check_stale(self):
        """Warn when no PCAP activity (helps diagnose missing Windows tshark)."""
        now = time.time()
        if self._incoming_recently_modified():
            self.stats["stale_message"] = None
            return
        if now - self._loop_started_at < self._stale_after_seconds:
            return
        if self._last_chunk_at and (now - self._last_chunk_at) < self._stale_after_seconds:
            return
        candidates = self._list_candidates()
        if not candidates:
            self.stats["stale_message"] = (
                "No PCAP files in incoming/. Run scripts/start_wifi_tshark_windows.ps1 on Windows."
            )
        elif self._last_chunk_at == 0:
            self.stats["stale_message"] = (
                "PCAP files present but not ingested yet (wait for stable write) or files are empty."
            )
        else:
            self.stats["stale_message"] = (
                f"No new PCAP chunks for {int(self._stale_after_seconds)}s. "
                "Check Windows tshark is still capturing."
            )

    def run_loop(self):
        """Blocking poll loop — run in a background thread."""
        self._ensure_dirs()
        self._capture = LiveCapture(
            on_alert_callback=self._on_flow,
            on_packet_callback=self.on_packet_callback,
        )
        self._loop_started_at = time.time()
        self._last_chunk_at = 0.0
        logger.info("tshark ingest watching %s", self.incoming_dir)
        while self.running:
            now = time.time()
            for path in self._list_candidates():
                if not self.running:
                    break
                key = str(path.resolve())
                if key in self._processed_files:
                    continue
                # Read new packets from growing files every poll (~real-time UI)
                if self._capture is not None:
                    self._read_new_packets(path, self._capture)
                if self._is_stable(path) and self._capture is not None:
                    self._finalize_and_archive(path, self._capture)
            self._check_stale()
            time.sleep(min(self.poll_interval, self._partial_poll_seconds))
        logger.info("tshark ingest stopped. stats=%s", self.stats)

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def get_status(self) -> dict:
        incoming_files = []
        try:
            incoming_files = [p.name for p in self._list_candidates()[:8]]
        except OSError:
            pass
        return {
            "active": self.running,
            "incoming_dir": str(self.incoming_dir),
            "processed_dir": str(self.processed_dir),
            "incoming_files": incoming_files,
            "stats": dict(self.stats),
        }


def ingest_stdin(on_flow_callback: Optional[Callable] = None):
    """
    Read PCAP stream from stdin (tshark -w - piped from Windows).
    Usage: tshark -i Wi-Fi -w - | python -m capture.tshark_ingest --stdin
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy required for stdin ingest")

    from scapy.utils import RawPcapReader

    capture = LiveCapture(on_alert_callback=on_flow_callback)
    reader = RawPcapReader(sys.stdin.buffer)
    for pkt_data, _ in reader:
        try:
            from scapy.all import Ether
            pkt = Ether(pkt_data)
            capture._process_packet(pkt)
        except Exception:
            continue
    for flow in capture.flows.values():
        capture._finalise_flow(flow)
    return capture.stats


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="FedAIDA tshark PCAP ingest")
    parser.add_argument("--watch", action="store_true", help="Watch incoming/ folder")
    parser.add_argument("--file", type=str, help="Process one PCAP file")
    parser.add_argument("--stdin", action="store_true", help="Read PCAP from stdin")
    parser.add_argument("--incoming", default=DEFAULT_INCOMING)
    parser.add_argument("--processed", default=DEFAULT_PROCESSED)
    args = parser.parse_args()

    def _print_flow(info):
        print(
            f"[FLOW] {info['src_ip']} -> {info['dst_ip']}:{info['dst_port']} "
            f"| pkts={info['pkt_count']}"
        )

    cb = _print_flow
    if args.stdin:
        ingest_stdin(cb)
    elif args.file:
        ing = TsharkIngest(on_flow_callback=cb, incoming_dir=args.incoming)
        ing.running = True
        print(ing.ingest_file(args.file))
    elif args.watch:
        ing = TsharkIngest(
            on_flow_callback=cb,
            incoming_dir=args.incoming,
            processed_dir=args.processed,
        )
        ing.start()
        try:
            ing.run_loop()
        except KeyboardInterrupt:
            ing.stop()
    else:
        parser.print_help()
