#!/usr/bin/env python3
# ============================================================
# dashboard/app.py
# Real-Time FedAIDA-IDS Dashboard
# Flask + SocketIO — live alerts, trust scores, FL rounds
# ============================================================

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import numpy as np
import threading
import time
import json
import logging
from datetime import datetime, timezone
from collections import deque

from config import (
    DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_DEBUG,
    MODEL_DIR, SEQUENCE_LEN, NUM_FEATURES, NUM_CLASSES,
    ATTACK_NAMES, ALERT_CONFIDENCE_THRESHOLD, MIN_FLOW_PACKETS,
    TSHARK_INCOMING_DIR, TSHARK_PROCESSED_DIR,
    SCAN_WINDOW_SEC, SCAN_MIN_UNIQUE_PORTS, SCAN_MIN_SYN_EVENTS,
    LAN_SCAN_ENABLED,
    SCAN_BURST_WINDOW_SEC, SCAN_BURST_MIN_PORTS, SCAN_BURST_MIN_SYN_EVENTS,
    SCAN_LOCAL_BURST_MIN_PORTS,
    SCAN_ALERT_COOLDOWN_SEC, SCAN_HEURISTIC_THRESHOLD, SCAN_EXCLUDE_PORTS,
    LAN_ARP_SWEEP_ENABLED, LAN_ARP_WINDOW_SEC, LAN_ARP_MIN_HOSTS, LAN_ARP_COOLDOWN_SEC,
    LIVE_ALERT_MODE, LIVE_ML_ALERT_CONFIDENCE, PROBE_CLASS_ID,
    LOCAL_IP_WHITELIST, DONT_AUTO_BLOCK_LOCAL_IPS,
    LAN_SCAN_VICTIM_ALERT_ONLY,
)
from capture.scan_detector import ScanTracker, ArpScanTracker
from capture.network_utils import (
    get_local_ipv4_addresses,
    get_windows_wifi_ipv4_addresses,
    merge_local_ips,
)

logger = logging.getLogger("dashboard")
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
_allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "DASHBOARD_CORS_ORIGINS", "http://localhost:5000,http://127.0.0.1:5000"
    ).split(",")
    if origin.strip()
]
_api_key = os.getenv("DASHBOARD_API_KEY", "").strip()

CORS(app, resources={r"/api/*": {"origins": _allowed_origins}})
socketio = SocketIO(app, cors_allowed_origins=_allowed_origins, async_mode='eventlet')

# ── Global state ────────────────────────────────────────────
STATE = {
    'model':           None,
    'scaler':          None,
    'alert_count':     0,
    'recent_alerts':   deque(maxlen=200),
    'blocked_ips':     {},
    'n_flows_seen':    0,
    'n_attacks_seen':  0,
    'attack_counts':   {},
    'tshark_active':   False,
    'tshark_stats':    {},
    'traffic_log':     deque(maxlen=1000),
    'packet_no':       0,
    'last_packet_at':  None,
    'last_packet_epoch': None,
    'local_ips':       set(),
    'lan_scan_packets': 0,
}
_tshark_runtime = {
    "ingest": None,
    "thread": None,
}

_ALERT_CONF = float(os.getenv("DASHBOARD_ALERT_CONFIDENCE", str(ALERT_CONFIDENCE_THRESHOLD)))
_MIN_FLOW_PKTS = int(os.getenv("DASHBOARD_MIN_FLOW_PKTS", str(MIN_FLOW_PACKETS)))

_LABEL_PORTSCAN = "PortScan (nmap suspected)"
_LABEL_PROBE_AI = "Probe (scan suspected)"

_scan_tracker = ScanTracker(
    window_sec=float(os.getenv("SCAN_WINDOW_SEC", str(SCAN_WINDOW_SEC))),
    min_unique_ports=int(os.getenv("SCAN_MIN_UNIQUE_PORTS", str(SCAN_MIN_UNIQUE_PORTS))),
    min_syn_events=int(os.getenv("SCAN_MIN_SYN_EVENTS", str(SCAN_MIN_SYN_EVENTS))),
    heuristic_threshold=float(
        os.getenv("SCAN_HEURISTIC_THRESHOLD", str(SCAN_HEURISTIC_THRESHOLD))
    ),
    cooldown_sec=float(os.getenv("SCAN_ALERT_COOLDOWN_SEC", str(SCAN_ALERT_COOLDOWN_SEC))),
    burst_window_sec=float(os.getenv("SCAN_BURST_WINDOW_SEC", str(SCAN_BURST_WINDOW_SEC))),
    burst_min_ports=int(os.getenv("SCAN_BURST_MIN_PORTS", str(SCAN_BURST_MIN_PORTS))),
    burst_min_syn_events=int(
        os.getenv("SCAN_BURST_MIN_SYN_EVENTS", str(SCAN_BURST_MIN_SYN_EVENTS))
    ),
    exclude_ports=set(SCAN_EXCLUDE_PORTS),
    local_burst_min_ports=int(
        os.getenv("SCAN_LOCAL_BURST_MIN_PORTS", str(SCAN_LOCAL_BURST_MIN_PORTS))
    ),
    lan_subnet_only=True,
)
_arp_tracker = ArpScanTracker(
    window_sec=float(os.getenv("LAN_ARP_WINDOW_SEC", str(LAN_ARP_WINDOW_SEC))),
    min_unique_hosts=int(os.getenv("LAN_ARP_MIN_HOSTS", str(LAN_ARP_MIN_HOSTS))),
    cooldown_sec=float(os.getenv("LAN_ARP_COOLDOWN_SEC", str(LAN_ARP_COOLDOWN_SEC))),
)
_LAN_SCAN_ON = os.getenv("LAN_SCAN_ENABLED", str(LAN_SCAN_ENABLED)).lower() in (
    "1", "true", "yes", "on"
)
_LAN_ARP_ON = os.getenv("LAN_ARP_SWEEP_ENABLED", str(LAN_ARP_SWEEP_ENABLED)).lower() in (
    "1", "true", "yes", "on"
)
_LIVE_ALERT_MODE = os.getenv("LIVE_ALERT_MODE", LIVE_ALERT_MODE).strip().lower()
_LIVE_ML_CONF = float(os.getenv("LIVE_ML_ALERT_CONFIDENCE", str(LIVE_ML_ALERT_CONFIDENCE)))
_LAN_CHECK_EVERY_N_PACKETS = 25
_LAN_VICTIM_ALERT_ONLY = os.getenv(
    "LAN_SCAN_VICTIM_ALERT_ONLY", str(LAN_SCAN_VICTIM_ALERT_ONLY)
).strip().lower() in ("1", "true", "yes")
_LOCAL_IP_REFRESH_SEC = float(os.getenv("LOCAL_IP_REFRESH_SEC", "90"))
_last_local_ip_refresh = 0.0


def _parse_local_ip_whitelist() -> set:
    extra = os.getenv("DASHBOARD_LOCAL_IPS", "").strip()
    ips = {ip.strip() for ip in LOCAL_IP_WHITELIST if str(ip).strip()}
    if extra:
        ips.update(ip.strip() for ip in extra.split(",") if ip.strip())
    return ips


def _refresh_local_ips():
    ips = merge_local_ips(
        get_local_ipv4_addresses(),
        _parse_local_ip_whitelist(),
        windows_wifi=get_windows_wifi_ipv4_addresses(),
    )
    STATE["local_ips"] = ips
    _scan_tracker.set_local_ips(ips)
    _unblock_whitelisted_ips()
    logger.info("LAN scan monitor: local IPs %s", sorted(ips) if ips else "(none detected)")
    return ips


def _maybe_refresh_local_ips(force: bool = False):
    """Re-detect Windows Wi-Fi IP (DHCP changes; WSL PATH may miss powershell.exe)."""
    global _last_local_ip_refresh
    now = time.time()
    if not force and (now - _last_local_ip_refresh) < _LOCAL_IP_REFRESH_SEC:
        return
    _last_local_ip_refresh = now
    before = set(STATE.get("local_ips", ()))
    after = _refresh_local_ips()
    if after != before:
        logger.info("Local IPs changed %s -> %s", sorted(before), sorted(after))


def _is_local_ip(ip: str) -> bool:
    return bool(ip) and ip in STATE.get("local_ips", set())


def _unblock_whitelisted_ips():
    """Remove auto-blocks on this laptop's IP(s) after whitelist refresh."""
    for ip in list(STATE["blocked_ips"]):
        if _is_local_ip(ip):
            del STATE["blocked_ips"][ip]
            socketio.emit("ip_unblocked", {"ip": ip})


def _utc_now_fields() -> tuple[str, float]:
    now = datetime.now(timezone.utc)
    return now.isoformat().replace("+00:00", "Z"), now.timestamp()


def _candidate_weight_paths(dataset):
    ds = (dataset or "").strip().lower().replace("-", "_")
    aliases = [ds]
    if ds == "bot_iot":
        aliases.append("botiot")
    if ds == "botiot":
        aliases.append("bot_iot")
    if ds == "nsl_kdd":
        aliases.append("nslkdd")
    if ds == "nslkdd":
        aliases.append("nsl_kdd")

    names = []
    for alias in aliases:
        if alias:
            names.extend([
                f"fedaida_global_{alias}.weights.h5",
                f"fedaida_{alias}.weights.h5",
            ])
    names.extend([
        "best_global_model.weights.h5",
        "final_global_model.weights.h5",
    ])
    # Preserve order while removing duplicates.
    ordered_unique = []
    seen = set()
    for name in names:
        if name not in seen:
            ordered_unique.append(os.path.join(MODEL_DIR, name))
            seen.add(name)
    return ordered_unique


def _first_existing_weight(dataset):
    for path in _candidate_weight_paths(dataset):
        if os.path.exists(path):
            return path
    return None


def _is_authorized():
    if not _api_key:
        return False
    supplied = (
        request.headers.get("X-API-Key")
        or request.headers.get("Authorization", "").replace("Bearer ", "")
        or request.args.get("api_key", "")
    ).strip()
    return bool(supplied) and supplied == _api_key


def _require_api_key():
    if _is_authorized():
        return None
    return jsonify({
        "status": "error",
        "message": "Unauthorized. Set DASHBOARD_API_KEY and provide X-API-Key.",
    }), 401


# ── Routes ───────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/refresh_local_ips', methods=['POST'])
def refresh_local_ips_api():
    """Re-detect this laptop's Wi-Fi IP (WSL + Windows). Requires API key if configured."""
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    _maybe_refresh_local_ips(force=True)
    return jsonify({
        "status": "ok",
        "local_ips": sorted(STATE.get("local_ips", [])),
        "lan_scan_victim_only": _LAN_VICTIM_ALERT_ONLY,
    })


@app.route('/api/status')
def status():
    ingest = _tshark_runtime.get("ingest")
    if ingest is not None:
        STATE["tshark_stats"] = ingest.get_status().get("stats", {})
    tstats = STATE.get("tshark_stats", {})
    stale_msg = tstats.get("stale_message")
    incoming_files = tstats.get("incoming_files", [])
    return jsonify({
        'model_loaded':   STATE['model'] is not None,
        'alert_count':    STATE['alert_count'],
        'flows_seen':     STATE['n_flows_seen'],
        'tshark_flows':   tstats.get('flows', 0),
        'tshark_packets': tstats.get('packets', 0),
        'attacks_seen':   STATE['n_attacks_seen'],
        'tshark_active':  STATE['tshark_active'],
        'tshark_stats':   tstats,
        'traffic_packets': len(STATE['traffic_log']),
        'packet_no':      STATE['packet_no'],
        'last_packet_at': STATE.get('last_packet_at'),
        'last_packet_epoch': STATE.get('last_packet_epoch'),
        'tshark_stale_message': stale_msg,
        'tshark_incoming_files': incoming_files,
        'scan_detection_active': True,
        'live_alert_mode': _LIVE_ALERT_MODE,
        'lan_scan_enabled': _LAN_SCAN_ON,
        'local_ips': sorted(STATE.get("local_ips", [])),
        'scan_burst_sec': SCAN_BURST_WINDOW_SEC,
        'lan_scan_victim_only': _LAN_VICTIM_ALERT_ONLY,
    })


@app.route('/api/alerts')
def get_alerts():
    return jsonify(list(STATE['recent_alerts']))


@app.route('/api/blocked')
def get_blocked():
    return jsonify(STATE['blocked_ips'])


@app.route('/api/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    if ip in STATE['blocked_ips']:
        del STATE['blocked_ips'][ip]
        socketio.emit('ip_unblocked', {'ip': ip})
        return jsonify({'status': 'ok', 'message': f'{ip} unblocked'})
    return jsonify({'status': 'error', 'message': 'IP not found'})


@app.route('/api/unblock_all', methods=['POST'])
def unblock_all():
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    STATE['blocked_ips'].clear()
    socketio.emit('all_unblocked', {})
    return jsonify({'status': 'ok'})


@app.route('/api/load_model', methods=['POST'])
def load_model_api():
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    data     = request.json or {}
    dataset  = data.get('dataset', 'bot_iot')
    n_classes = int(data.get('n_classes', 6))

    try:
        from model.fedaida_model import build_fedaida_model
        model     = build_fedaida_model(n_classes=n_classes)
        wpath = _first_existing_weight(dataset)
        if wpath and os.path.exists(wpath):
            try:
                model.load_weights(wpath)
                STATE['model'] = model
                msg = f"Model loaded from {wpath}"
            except Exception as e:
                logger.warning("Failed to load weights %s: %s", wpath, e)
                STATE['model'] = model
                msg = f"Weight load failed ({os.path.basename(wpath)}); using untrained model for demo"
        else:
            # Use untrained model for demo
            STATE['model'] = model
            msg = "No saved weights — using untrained model (for demo only)"

        socketio.emit('model_status', {'loaded': True, 'message': msg})
        return jsonify({'status': 'ok', 'message': msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/update_fl_round', methods=['POST'])
def update_fl_round():
    """Called by training script to push FL round updates to dashboard."""
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    data = request.json or {}
    _update_fl_state(data)
    return jsonify({'status': 'ok'})


@app.route('/api/traffic')
def get_traffic():
    """Wireshark-style packet rows plus IDS detection columns."""
    limit = min(int(request.args.get('limit', 200)), 1000)
    rows = sorted(
        list(STATE['traffic_log'])[:limit],
        key=lambda r: (float(r.get("time_epoch") or 0), int(r.get("no") or 0)),
        reverse=True,
    )
    return jsonify({
        'packets': rows,
        'total_buffered': len(STATE['traffic_log']),
        'packet_no': STATE['packet_no'],
    })


@app.route('/api/export_log')
def export_log():
    """Export audit log as JSON."""
    log = {
        'exported_at':    datetime.now().isoformat(),
        'total_flows':    STATE['n_flows_seen'],
        'total_attacks':  STATE['n_attacks_seen'],
        'alerts':         list(STATE['recent_alerts']),
        'blocked_ips':    STATE['blocked_ips'],
    }
    return jsonify(log)


@app.route('/api/capture/tshark/status', methods=['GET'])
def tshark_status():
    ingest = _tshark_runtime.get("ingest")
    if ingest is not None:
        STATE["tshark_stats"] = ingest.get_status().get("stats", {})
    return jsonify({
        "active": STATE["tshark_active"],
        "incoming_dir": TSHARK_INCOMING_DIR,
        "stats": STATE.get("tshark_stats", {}),
    })


@app.route('/api/capture/tshark/start', methods=['POST'])
def start_tshark_ingest():
    """Watch Windows tshark rolling PCAP chunks in capture/incoming/."""
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    if STATE["tshark_active"]:
        return jsonify({"status": "ok", "message": "tshark ingest already running"})

    _refresh_local_ips()
    STATE["lan_scan_packets"] = 0

    data = request.json or {}
    incoming = data.get("incoming_dir") or TSHARK_INCOMING_DIR
    processed = data.get("processed_dir") or TSHARK_PROCESSED_DIR
    poll = float(data.get("poll_interval", 1.0))
    stable = float(data.get("stable_seconds", 1.5))

    try:
        from capture.tshark_ingest import TsharkIngest
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    on_packet, on_flow = _make_capture_callbacks()

    ingest = TsharkIngest(
        on_flow_callback=on_flow,
        on_packet_callback=on_packet,
        incoming_dir=incoming,
        processed_dir=processed,
        poll_interval=poll,
        stable_seconds=stable,
        min_flow_packets=_MIN_FLOW_PKTS,
    )

    def _run():
        try:
            ingest.run_loop()
        finally:
            STATE["tshark_active"] = False
            STATE["tshark_stats"] = ingest.get_status().get("stats", {})
            _tshark_runtime["ingest"] = None
            _tshark_runtime["thread"] = None
            socketio.emit("tshark_status", {"active": False, "stats": STATE["tshark_stats"]})

    ingest.start()
    thread = threading.Thread(target=_run, daemon=True)
    _tshark_runtime["ingest"] = ingest
    _tshark_runtime["thread"] = thread
    STATE["tshark_active"] = True
    thread.start()
    msg = f"Watching {incoming} — run start_wifi_tshark_windows.ps1 on Windows for Wi-Fi packets."
    socketio.emit("tshark_status", {
        "active": True,
        "incoming_dir": str(ingest.incoming_dir),
        "message": msg,
    })
    return jsonify({
        "status": "ok",
        "message": msg,
        "incoming_dir": incoming,
    })


@app.route('/api/capture/tshark/stop', methods=['POST'])
def stop_tshark_ingest():
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    ingest = _tshark_runtime.get("ingest")
    if ingest is not None:
        ingest.stop()
    STATE["tshark_active"] = False
    socketio.emit("tshark_status", {"active": False})
    return jsonify({"status": "ok", "message": "tshark ingest stop requested"})


@app.route('/api/capture/tshark/upload', methods=['POST'])
def upload_tshark_pcap():
    """Upload a single PCAP/PCAPNG for immediate analysis (Wireshark export)."""
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file in multipart form (field: file)"}), 400

    f = request.files["file"]
    os.makedirs(TSHARK_INCOMING_DIR, exist_ok=True)
    safe_name = os.path.basename(f.filename or "upload.pcapng")
    dest = os.path.join(TSHARK_INCOMING_DIR, f"upload_{int(time.time())}_{safe_name}")
    f.save(dest)

    try:
        from capture.tshark_ingest import TsharkIngest

        on_packet, on_flow = _make_capture_callbacks()

        ing = TsharkIngest(
            on_flow_callback=on_flow,
            on_packet_callback=on_packet,
            incoming_dir=TSHARK_INCOMING_DIR,
            processed_dir=TSHARK_PROCESSED_DIR,
            min_flow_packets=_MIN_FLOW_PKTS,
        )
        ing.running = True
        result = ing.ingest_file(dest)
        return jsonify({"status": "ok", "message": "PCAP processed", **result})
    except Exception as e:
        logger.exception("PCAP upload ingest failed")
        return jsonify({"status": "error", "message": str(e)}), 500


# ── SocketIO Events ─────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    emit('initial_state', {
        'alert_count':   STATE['alert_count'],
        'model_loaded':  STATE['model'] is not None,
        'tshark_active': STATE['tshark_active'],
        'tshark_stats': STATE.get('tshark_stats', {}),
    })


# ── Internal Logic ───────────────────────────────────────────

def _raise_lan_scan_hit(scan_eval: dict, flow_meta: dict | None = None) -> bool:
    """Emit LAN port-scan alert from evaluate() result."""
    if not _LAN_SCAN_ON or not scan_eval.get("suspected"):
        return False
    scanner = scan_eval.get("scanner_ip") or (flow_meta or {}).get("src_ip", "")
    victim = scan_eval.get("dst_ip") or (flow_meta or {}).get("dst_ip", "")
    if not scanner or not victim:
        return False
    return _maybe_raise_scan_alert(scan_eval, scanner, flow_meta)


def _raise_arp_sweep_hit(arp_eval: dict) -> bool:
    if not _LAN_ARP_ON or not arp_eval.get("suspected"):
        return False
    scanner = arp_eval.get("scanner_ip", "")
    if not scanner or not _arp_tracker.can_alert(scanner):
        return False
    evidence = arp_eval.get("scan_evidence", "")
    conf = max(float(arp_eval.get("score", 0.0)), _ALERT_CONF)
    _arp_tracker.mark_alert(scanner)
    _emit_ids_alert(
        scanner,
        "ARP sweep (host discovery)",
        conf,
        f"IF many_arp_who_has THEN host discovery on LAN",
        {"dst_ip": "LAN", "protocol": "ARP", "bytes": 0, "pkt_count": 0},
        detection_method="arp",
        scan_evidence=evidence,
    )
    return True


def _check_lan_scans(scanner_hint: str | None = None) -> None:
    """Evaluate all visible LAN scanners and raise alerts (same Wi-Fi)."""
    if not _LAN_SCAN_ON:
        return
    hits = _scan_tracker.evaluate_all(scanner_ip=scanner_hint)
    for hit in hits:
        _raise_lan_scan_hit(hit, None)
    if _LAN_ARP_ON:
        for arp_hit in _arp_tracker.evaluate_all():
            _raise_arp_sweep_hit(arp_hit)


def _record_scan_from_flow(flow_meta: dict) -> dict:
    """Feed flow stats into ScanTracker and return evaluation for scanner IP."""
    if not flow_meta:
        return _scan_tracker.evaluate("")
    proto = (flow_meta.get("protocol") or "").upper()
    if proto != "TCP":
        return _scan_tracker.evaluate(flow_meta.get("src_ip", ""))
    src_ip = flow_meta.get("src_ip") or ""
    dst_ip = flow_meta.get("dst_ip") or ""
    if not src_ip or not dst_ip:
        return _scan_tracker.evaluate(src_ip)
    syn_count = int(flow_meta.get("syn_count") or 0)
    pkt_count = int(flow_meta.get("pkt_count") or 1)
    duration = float(flow_meta.get("duration") or 0.0)
    # Skip normal TCP sessions (many packets / long-lived) — not nmap-style probes
    if syn_count < 1 or pkt_count > 4 or (duration > 2.5 and pkt_count > 2):
        return _scan_tracker.evaluate(src_ip)
    is_syn = True
    _scan_tracker.record_flow(
        src_ip,
        dst_ip,
        int(flow_meta.get("dst_port") or 0),
        is_syn=is_syn,
        pkt_count=pkt_count,
        duration=float(flow_meta.get("duration") or 0.0),
    )
    return _scan_tracker.evaluate(src_ip)


def _record_arp_scan(row: dict) -> None:
    if row.get("arp_op") != "who-has":
        return
    requester = row.get("src_ip") or ""
    target = row.get("arp_target_ip") or row.get("dst_ip") or ""
    if requester and target:
        _arp_tracker.record_who_has(requester, target)


def _is_syn_probe_row(row: dict) -> bool:
    """True for bare SYN (half-open probe), not SYN-ACK or normal sessions."""
    if row.get("is_syn_probe") is not None:
        return bool(row["is_syn_probe"])
    flags = row.get("tcp_flags")
    if flags is not None:
        return bool(flags & 0x02) and not bool(flags & 0x10)
    return bool(row.get("is_syn"))


def _record_scan_from_packet(row: dict) -> None:
    """Update scan tracker only (no alert) — alerts fire on flow aggregation."""
    if not _is_syn_probe_row(row):
        return
    if (row.get("protocol") or "").upper() != "TCP":
        return
    src_ip = row.get("src_ip") or ""
    dst_ip = row.get("dst_ip") or ""
    dst_port = row.get("dst_port")
    if not src_ip or not dst_ip or dst_port is None:
        return
    _scan_tracker.record_packet_syn(src_ip, dst_ip, int(dst_port))
    STATE["lan_scan_packets"] = STATE.get("lan_scan_packets", 0) + 1
    if STATE["lan_scan_packets"] % _LAN_CHECK_EVERY_N_PACKETS == 0:
        _maybe_refresh_local_ips()
        _check_lan_scans(scanner_hint=src_ip)


def _fuse_attack_labels(scan_eval: dict, pred: int, ml_name: str, ml_conf: float,
                        *, live_traffic: bool = False) -> tuple:
    """Return (is_attack, display_name, confidence, detection_method, fuzzy_rule)."""
    rules_hit = bool(scan_eval.get("suspected"))
    if live_traffic:
        rules_hit = False
    ml_conf_threshold = _LIVE_ML_CONF if live_traffic else _ALERT_CONF
    ml_probe = pred == PROBE_CLASS_ID and ml_conf >= ml_conf_threshold
    ml_other = (not live_traffic) and pred != 0 and ml_conf >= _ALERT_CONF
    if live_traffic and _LIVE_ALERT_MODE == "scan_only":
        ml_probe = False
        ml_other = False

    if rules_hit and ml_probe:
        conf = max(float(scan_eval.get("score", 0.0)), ml_conf)
        rule = (
            f"IF many_ports AND syn_probes THEN {_LABEL_PORTSCAN} "
            f"(rules+AI Probe {ml_conf:.0%})"
        )
        return True, _LABEL_PORTSCAN, conf, "rules+ai", rule

    if rules_hit:
        conf = max(float(scan_eval.get("score", 0.0)), _ALERT_CONF)
        rule = scan_eval.get("fuzzy_rule") or (
            f"IF unique_dst_ports >= threshold THEN {_LABEL_PORTSCAN}"
        )
        return True, _LABEL_PORTSCAN, conf, "rules", rule

    if ml_probe:
        rule = f"IF traffic_pattern IS PROBE THEN {_LABEL_PROBE_AI}"
        return True, _LABEL_PROBE_AI, ml_conf, "ai", rule

    if ml_other:
        return True, ml_name, ml_conf, "ai", f"IF traffic_pattern IS ANOMALOUS THEN {ml_name}"

    return False, "Normal", ml_conf, "", ""


def _emit_ids_alert(
    src_ip: str,
    attack_type: str,
    confidence: float,
    fuzzy_rule: str,
    flow_meta,
    *,
    detection_method: str = "",
    scan_evidence: str = "",
    blocked_override: bool | None = None,
):
    """Create alert row, annotate traffic, optionally auto-block."""
    STATE["n_attacks_seen"] += 1
    STATE["attack_counts"][attack_type] = STATE["attack_counts"].get(attack_type, 0) + 1
    STATE["alert_count"] += 1

    sev = _severity(confidence)
    ts_iso, ts_epoch = _utc_now_fields()
    alert = {
        "id": STATE["alert_count"],
        "timestamp": ts_iso,
        "timestamp_epoch": ts_epoch,
        "src_ip": src_ip,
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
        "fuzzy_rule": fuzzy_rule,
        "severity": sev,
        "blocked": False,
        "dst_ip": "—",
        "protocol": "—",
        "length": None,
        "info": scan_evidence or "",
        "detection_method": detection_method,
        "scan_evidence": scan_evidence,
    }
    if flow_meta:
        alert.update(_alert_fields_from_flow(flow_meta, src_ip))
        if scan_evidence and not alert.get("info"):
            alert["info"] = scan_evidence

    do_block = blocked_override if blocked_override is not None else confidence > 0.95
    if DONT_AUTO_BLOCK_LOCAL_IPS and _is_local_ip(src_ip):
        do_block = False
    if do_block and src_ip not in STATE["blocked_ips"]:
        STATE["blocked_ips"][src_ip] = {
            "blocked_at": datetime.now().isoformat(),
            "attack_type": attack_type,
            "confidence": confidence,
            "auto_expires": True,
        }
        alert["blocked"] = True
        socketio.emit(
            "ip_blocked",
            {"ip": src_ip, "attack_type": attack_type, "confidence": confidence},
        )

    STATE["recent_alerts"].appendleft(alert)
    socketio.emit("new_alert", alert)


def _maybe_raise_scan_alert(
    scan_eval: dict,
    scanner_ip: str,
    flow_meta: dict | None,
    *,
    raise_alerts: bool = True,
) -> bool:
    """Raise LAN port-scan alert: scanner_ip probing victim dst_ip."""
    if not scan_eval.get("suspected"):
        return False
    victim_ip = scan_eval.get("dst_ip") or (flow_meta or {}).get("dst_ip", "")
    if not victim_ip or not _scan_tracker.can_alert(scanner_ip, victim_ip):
        return False

    if _LAN_VICTIM_ALERT_ONLY and not _is_local_ip(victim_ip):
        return False

    evidence = scan_eval.get("scan_evidence") or scan_eval.get("reason", "")
    conf = max(float(scan_eval.get("score", 0.0)), _ALERT_CONF)
    display = _LABEL_PORTSCAN

    if flow_meta:
        _annotate_traffic_detection(
            flow_meta.get("src_ip", scanner_ip),
            flow_meta.get("dst_ip", ""),
            flow_meta.get("src_port"),
            flow_meta.get("dst_port"),
            display,
            conf,
            _severity(conf),
            True,
            scan_evidence=evidence,
        )
    elif scanner_ip and victim_ip:
        _annotate_traffic_detection(
            scanner_ip, victim_ip, None, None, display, conf, _severity(conf), True,
            scan_evidence=evidence,
        )

    if raise_alerts:
        _scan_tracker.mark_alert(scanner_ip, victim_ip)
        meta = dict(flow_meta) if flow_meta else {
            "src_ip": scanner_ip,
            "dst_ip": victim_ip,
            "protocol": "TCP",
            "bytes": 0,
            "pkt_count": scan_eval.get("syn_events", 0),
        }
        fuzzy_rule = scan_eval.get("fuzzy_rule") or f"IF LAN_port_scan THEN {display}"
        _emit_ids_alert(
            scanner_ip,
            display,
            conf,
            fuzzy_rule,
            meta,
            detection_method="lan_scan",
            scan_evidence=evidence,
        )
    return True


def _register_packet_row(row: dict):
    """Store Wireshark-compatible packet row and push to browsers."""
    STATE['packet_no'] += 1
    row = dict(row)
    row['no'] = STATE['packet_no']
    row['source_tag'] = 'live'
    STATE['traffic_log'].appendleft(row)
    epoch = row.get("time_epoch")
    if epoch is not None:
        try:
            STATE["last_packet_epoch"] = float(epoch)
            pkt_dt = datetime.fromtimestamp(STATE["last_packet_epoch"], tz=timezone.utc)
            STATE["last_packet_at"] = pkt_dt.isoformat().replace("+00:00", "Z")
        except (TypeError, ValueError, OSError):
            ts_iso, _ = _utc_now_fields()
            STATE["last_packet_at"] = ts_iso
    else:
        ts_iso, _ = _utc_now_fields()
        STATE["last_packet_at"] = ts_iso
    socketio.emit('traffic_packet', row)
    if row.get("protocol") == "ARP":
        _record_arp_scan(row)
        if _LAN_ARP_ON and STATE.get("lan_scan_packets", 0) % 10 == 0:
            _check_lan_scans()
    else:
        _record_scan_from_packet(row)


def _flow_info_string(flow_meta: dict) -> str:
    """Wireshark-style summary for alert / flow rows."""
    proto = flow_meta.get('protocol', '')
    sp = flow_meta.get('src_port')
    dp = flow_meta.get('dst_port')
    if sp is not None and dp is not None:
        return f"{sp} → {dp} | {flow_meta.get('pkt_count', 0)} pkts, {flow_meta.get('bytes', 0)} bytes"
    return f"{proto} | {flow_meta.get('pkt_count', 0)} pkts, {flow_meta.get('bytes', 0)} bytes"


def _alert_fields_from_flow(flow_meta: dict, src_ip: str) -> dict:
    """Protocol / destination / length for alert table when flow is real."""
    return {
        'dst_ip': flow_meta.get('dst_ip') or '—',
        'protocol': flow_meta.get('protocol') or '—',
        'length': flow_meta.get('bytes'),
        'info': _flow_info_string(flow_meta),
    }


def _annotate_traffic_detection(src_ip, dst_ip, src_port, dst_port,
                                detection, confidence, severity, is_attack,
                                scan_evidence=""):
    """Attach flow-level IDS result to matching packet rows (Wireshark + IDS view)."""
    for row in STATE['traffic_log']:
        if row.get('src_ip') and row.get('dst_ip'):
            match_fwd = (
                row.get('src_ip') == src_ip and row.get('dst_ip') == dst_ip
                and (src_port is None or row.get('src_port') == src_port)
                and (dst_port is None or row.get('dst_port') == dst_port)
            )
            match_rev = (
                row.get('src_ip') == dst_ip and row.get('dst_ip') == src_ip
                and (dst_port is None or row.get('src_port') == dst_port)
                and (src_port is None or row.get('dst_port') == src_port)
            )
            if match_fwd or match_rev:
                row['detection'] = detection
                row['confidence'] = round(confidence, 4) if confidence is not None else None
                row['severity'] = severity
                row['is_attack'] = is_attack
                if scan_evidence:
                    row['scan_evidence'] = scan_evidence
    payload = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'detection': detection,
        'confidence': confidence,
        'severity': severity,
        'is_attack': is_attack,
    }
    if scan_evidence:
        payload['scan_evidence'] = scan_evidence
    socketio.emit('traffic_detection', payload)


def _make_capture_callbacks():
    """Shared flow + packet handlers for live capture and tshark ingest."""

    def _on_packet(row):
        _register_packet_row(row)

    def _on_flow(flow_info):
        features = flow_info.get('features')
        src_ip = flow_info.get('src_ip', '0.0.0.0')
        if features is None:
            return
        scan_eval = _record_scan_from_flow(flow_info)
        _raise_lan_scan_hit(scan_eval, flow_info)
        pkt_count = flow_info.get('pkt_count', 0)
        if pkt_count < _MIN_FLOW_PKTS:
            return
        _process_flow(
            np.asarray(features, dtype=np.float32),
            src_ip=src_ip,
            min_packets=_MIN_FLOW_PKTS,
            flow_meta=flow_info,
            scan_eval=scan_eval,
        )

    return _on_packet, _on_flow


def _process_flow(flow_features, src_ip="0.0.0.0",
                   min_packets=0, flow_meta=None,
                   raise_alerts=True, scan_eval=None):
    """Process one network flow through the model and emit alert if needed."""
    if flow_meta and flow_meta.get('pkt_count', 0) < min_packets:
        if scan_eval is None:
            scan_eval = _record_scan_from_flow(flow_meta)
        _raise_lan_scan_hit(scan_eval, flow_meta)
        return

    if scan_eval is None and flow_meta:
        scan_eval = _record_scan_from_flow(flow_meta)
    elif scan_eval is None:
        scan_eval = {}

    STATE['n_flows_seen'] += 1

    if STATE['model'] is None:
        if scan_eval.get("suspected") and raise_alerts:
            _raise_lan_scan_hit(scan_eval, flow_meta)
        elif flow_meta:
            _annotate_traffic_detection(
                flow_meta.get('src_ip', src_ip),
                flow_meta.get('dst_ip', ''),
                flow_meta.get('src_port'),
                flow_meta.get('dst_port'),
                'Model not loaded', None, '', False,
            )
        return

    try:
        import tensorflow as tf

        padded = np.tile(flow_features, (SEQUENCE_LEN, 1))
        if padded.shape[1] < NUM_FEATURES:
            padded = np.pad(padded, ((0, 0), (0, NUM_FEATURES - padded.shape[1])))
        elif padded.shape[1] > NUM_FEATURES:
            padded = padded[:, :NUM_FEATURES]
        seq_features = padded[np.newaxis, :, :]

        logits = STATE['model'](seq_features, training=False)
        probs = tf.nn.softmax(logits).numpy()[0]
        pred = int(np.argmax(probs))
        conf = float(np.max(probs))
        name = ATTACK_NAMES.get(pred, 'Unknown')
        try:
            anfis = STATE['model'].get_layer('anfis')
            rules = anfis.get_top_rule_for_sample()
            ml_rule = rules[0] if rules else ""
        except Exception:
            ml_rule = f"IF traffic_pattern IS ANOMALOUS THEN {name}"

        is_attack, display_name, alert_conf, method, fused_rule = _fuse_attack_labels(
            scan_eval, pred, name, conf,
            live_traffic=bool(flow_meta),
        )

        sev = _severity(alert_conf) if is_attack else ''
        evidence = scan_eval.get("scan_evidence", "") if scan_eval.get("suspected") else ""

        if flow_meta:
            _annotate_traffic_detection(
                flow_meta.get('src_ip', src_ip),
                flow_meta.get('dst_ip', ''),
                flow_meta.get('src_port'),
                flow_meta.get('dst_port'),
                display_name,
                alert_conf,
                sev,
                is_attack,
                scan_evidence=evidence,
            )

        if is_attack and raise_alerts:
            dst_for_cooldown = (
                scan_eval.get("dst_ip") if scan_eval.get("suspected")
                else (flow_meta or {}).get("dst_ip", "")
            )
            scanner = scan_eval.get("scanner_ip") or src_ip
            if scan_eval.get("suspected") and dst_for_cooldown:
                if not _scan_tracker.can_alert(scanner, dst_for_cooldown):
                    return
                _scan_tracker.mark_alert(scanner, dst_for_cooldown)

            rule_text = fused_rule or ml_rule
            _emit_ids_alert(
                src_ip,
                display_name,
                alert_conf,
                rule_text,
                flow_meta,
                detection_method=method,
                scan_evidence=evidence,
            )

        if STATE['n_flows_seen'] % 10 == 0:
            socketio.emit('flow_stats', {
                'flows_seen': STATE['n_flows_seen'],
                'attacks_seen': STATE['n_attacks_seen'],
                'attack_dist': STATE['attack_counts'],
            })

    except Exception:
        logger.exception("Flow processing failed for source IP %s", src_ip)


def _update_fl_state(data):
    """Training script hook (FL metrics; no live dashboard UI)."""
    logger.info(
        "FL update from trainer: round=%s avg_f1=%s",
        data.get("round"),
        data.get("avg_f1"),
    )


def _severity(confidence):
    if confidence > 0.90: return 'HIGH'
    if confidence > 0.75: return 'MEDIUM'
    return 'LOW'


if __name__ == '__main__':
    print("\n" + "="*55)
    print("  FedAIDA-IDS Real-Time Dashboard")
    print(f"  http://localhost:{DASHBOARD_PORT}")
    print("="*55 + "\n")

    try:
        from capture.live_capture import SCAPY_AVAILABLE
        if not SCAPY_AVAILABLE:
            print("[WARNING] Scapy not installed — tshark ingest will NOT work.")
            print("          Use: ./scripts/run_dashboard.sh  (activates .venv with scapy)")
    except Exception:
        pass

    os.makedirs(MODEL_DIR, exist_ok=True)

    # Auto-load model if available
    for ds in ['bot_iot', 'nsl_kdd', 'cicids']:
        wpath = _first_existing_weight(ds)
        if wpath:
            from model.fedaida_model import build_fedaida_model
            m = build_fedaida_model()
            try:
                m.load_weights(wpath)
                STATE['model'] = m
                print(f"[Dashboard] Auto-loaded model: {wpath}")
                break
            except Exception as e:
                logger.warning("Auto-load skipped for %s: %s", wpath, e)

    _refresh_local_ips()

    socketio.run(
        app,
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=DASHBOARD_DEBUG
    )
