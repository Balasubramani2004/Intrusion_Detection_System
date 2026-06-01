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
    'is_monitoring':   False,
    'alert_count':     0,
    'fl_round':        0,
    'trust_scores':    [0.5] * 9,
    'quarantined':     [],
    'drift_nodes':     [],
    'recent_alerts':   deque(maxlen=200),
    'blocked_ips':     {},
    'n_flows_seen':    0,
    'n_attacks_seen':  0,
    'attack_counts':   {},
    'fl_history':      [],
    'capture_active':  False,
    'capture_interface': None,
    'tshark_active':   False,
    'tshark_stats':    {},
    'traffic_log':     deque(maxlen=1000),
    'packet_no':       0,
    'last_packet_at':  None,
}
_capture_runtime = {
    "capture": None,
    "thread": None,
}
_tshark_runtime = {
    "ingest": None,
    "thread": None,
}

_ALERT_CONF = float(os.getenv("DASHBOARD_ALERT_CONFIDENCE", str(ALERT_CONFIDENCE_THRESHOLD)))
_MIN_FLOW_PKTS = int(os.getenv("DASHBOARD_MIN_FLOW_PKTS", str(MIN_FLOW_PACKETS)))


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


@app.route('/api/status')
def status():
    ingest = _tshark_runtime.get("ingest")
    if ingest is not None:
        STATE["tshark_stats"] = ingest.get_status().get("stats", {})
    tstats = STATE.get("tshark_stats", {})
    stale_msg = tstats.get("stale_message")
    return jsonify({
        'monitoring':     STATE['is_monitoring'],
        'model_loaded':   STATE['model'] is not None,
        'fl_round':       STATE['fl_round'],
        'trust_scores':   STATE['trust_scores'],
        'quarantined':    STATE['quarantined'],
        'alert_count':    STATE['alert_count'],
        'flows_seen':     STATE['n_flows_seen'],
        'attacks_seen':   STATE['n_attacks_seen'],
        'tshark_active':  STATE['tshark_active'],
        'capture_active': STATE['capture_active'],
        'capture_interface': STATE.get('capture_interface'),
        'tshark_stats':   tstats,
        'traffic_packets': len(STATE['traffic_log']),
        'packet_no':      STATE['packet_no'],
        'last_packet_at': STATE.get('last_packet_at'),
        'tshark_stale_message': stale_msg,
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


@app.route('/api/simulate_attack', methods=['POST'])
def simulate_attack():
    """
    Inject a simulated attack flow for live demo.
    Generates synthetic flow features and runs inference.
    """
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    data        = request.json or {}
    attack_type = data.get('type', 'PortScan')
    src_ip      = data.get('src_ip', '192.168.1.100')

    flow = _generate_synthetic_flow(attack_type)
    _process_flow(flow, src_ip=src_ip, force_attack=True)
    return jsonify({'status': 'ok', 'message': f'Simulated {attack_type}'})


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
    rows = list(STATE['traffic_log'])[:limit]
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
        'fl_history':     STATE['fl_history'],
    }
    return jsonify(log)


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    data = request.json or {}
    interface = data.get("interface")
    packet_count = int(data.get("count", 0))

    if STATE["capture_active"]:
        return jsonify({"status": "ok", "message": "Capture already running"})

    try:
        from capture.live_capture import LiveCapture
    except Exception as e:
        return jsonify({"status": "error", "message": f"Capture import failed: {e}"}), 500

    on_packet, on_flow = _make_capture_callbacks()

    capture = LiveCapture(
        interface=interface,
        on_alert_callback=on_flow,
        on_packet_callback=on_packet,
    )
    def _run_capture():
        try:
            capture.start(interface=interface, packet_count=packet_count)
        finally:
            STATE["capture_active"] = False
            socketio.emit("capture_status", {
                "active": False,
                "interface": STATE.get("capture_interface"),
            })
            _capture_runtime["capture"] = None
            _capture_runtime["thread"] = None

    thread = threading.Thread(target=_run_capture, daemon=True)
    _capture_runtime["capture"] = capture
    _capture_runtime["thread"] = thread
    STATE["capture_active"] = True
    STATE["capture_interface"] = interface or "default"
    thread.start()
    socketio.emit("capture_status", {"active": True, "interface": STATE["capture_interface"]})
    return jsonify({
        "status": "ok",
        "message": f"Live capture started on {STATE['capture_interface']}",
    })


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    unauthorized = _require_api_key()
    if unauthorized:
        return unauthorized
    capture = _capture_runtime.get("capture")
    if capture is not None:
        try:
            capture.stop()
        except Exception:
            logger.exception("Failed to stop live capture cleanly")
    _capture_runtime["capture"] = None
    _capture_runtime["thread"] = None
    STATE["capture_active"] = False
    socketio.emit("capture_status", {"active": False, "interface": STATE.get("capture_interface")})
    return jsonify({"status": "ok", "message": "Live capture stop requested"})


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

    stopped_demo = _stop_demo_monitoring()
    STATE["traffic_log"].clear()
    STATE["packet_no"] = 0
    STATE["last_packet_at"] = None

    data = request.json or {}
    incoming = data.get("incoming_dir") or TSHARK_INCOMING_DIR
    processed = data.get("processed_dir") or TSHARK_PROCESSED_DIR
    poll = float(data.get("poll_interval", 1.0))

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
    msg = "tshark ingest watching {incoming}. Demo monitoring stopped.".format(incoming=incoming)
    if stopped_demo:
        msg += " Use Windows start_wifi_tshark_windows.ps1 for real Wi-Fi packets."
    socketio.emit("tshark_status", {
        "active": True,
        "incoming_dir": str(ingest.incoming_dir),
        "message": msg,
        "stopped_demo_monitoring": stopped_demo,
    })
    return jsonify({
        "status": "ok",
        "message": msg,
        "incoming_dir": incoming,
        "stopped_demo_monitoring": stopped_demo,
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

@socketio.on('start_monitoring')
def handle_start_monitoring(data):
    if not _api_key or (data or {}).get("api_key", "").strip() != _api_key:
        emit('monitoring_status', {'active': False, 'error': 'unauthorized'})
        return
    if not STATE['is_monitoring']:
        STATE['is_monitoring'] = True
        thread = threading.Thread(
            target=_monitoring_loop, daemon=True
        )
        thread.start()
        emit('monitoring_status', {
            'active': True,
            'demo_only': True,
            'message': 'Demo mode: synthetic flows only. No Protocol/Destination/Length. Use Start WiFi Capture (tshark) for real Wi-Fi.',
        })
        print("[Dashboard] Demo monitoring started (no alerts; use tshark for real traffic)")


@socketio.on('stop_monitoring')
def handle_stop_monitoring(data):
    if not _api_key or (data or {}).get("api_key", "").strip() != _api_key:
        emit('monitoring_status', {'active': STATE['is_monitoring'], 'error': 'unauthorized'})
        return
    STATE['is_monitoring'] = False
    emit('monitoring_status', {'active': False})
    print("[Dashboard] Monitoring stopped")


@socketio.on('connect')
def handle_connect():
    emit('initial_state', {
        'trust_scores':  STATE['trust_scores'],
        'quarantined':   STATE['quarantined'],
        'fl_round':      STATE['fl_round'],
        'alert_count':   STATE['alert_count'],
        'model_loaded':  STATE['model'] is not None,
        'capture_active': STATE['capture_active'],
        'capture_interface': STATE['capture_interface'],
        'tshark_active': STATE['tshark_active'],
        'tshark_stats': STATE.get('tshark_stats', {}),
    })


# ── Internal Logic ───────────────────────────────────────────

def _register_packet_row(row: dict):
    """Store Wireshark-compatible packet row and push to browsers."""
    STATE['packet_no'] += 1
    row = dict(row)
    row['no'] = STATE['packet_no']
    row['source_tag'] = 'live'
    STATE['traffic_log'].appendleft(row)
    STATE['last_packet_at'] = datetime.now(timezone.utc).isoformat()
    socketio.emit('traffic_packet', row)


def _stop_demo_monitoring():
    """Stop synthetic Start Monitoring when real capture begins."""
    if not STATE['is_monitoring']:
        return False
    STATE['is_monitoring'] = False
    socketio.emit('monitoring_status', {'active': False})
    logger.info("Stopped demo monitoring for real capture")
    return True


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
                                detection, confidence, severity, is_attack):
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
    socketio.emit('traffic_detection', {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'detection': detection,
        'confidence': confidence,
        'severity': severity,
        'is_attack': is_attack,
    })


def _make_capture_callbacks():
    """Shared flow + packet handlers for live capture and tshark ingest."""

    def _on_packet(row):
        _register_packet_row(row)

    def _on_flow(flow_info):
        features = flow_info.get('features')
        src_ip = flow_info.get('src_ip', '0.0.0.0')
        if features is None:
            return
        _process_flow(
            np.asarray(features, dtype=np.float32),
            src_ip=src_ip,
            force_attack=False,
            min_packets=_MIN_FLOW_PKTS,
            flow_meta=flow_info,
        )

    return _on_packet, _on_flow


def _monitoring_loop():
    """
    Main monitoring loop — simulates processing network flows.
    In real deployment: replace with Scapy packet capture.
    """
    import random
    attack_names_list = list(ATTACK_NAMES.values())

    while STATE['is_monitoring']:
        # Simulate a batch of network flows
        n_flows = random.randint(3, 8)
        for _ in range(n_flows):
            # 90% benign, 10% attack (realistic ratio)
            is_attack = random.random() < 0.10
            flow = _generate_synthetic_flow(
                'BENIGN' if not is_attack
                else random.choice(attack_names_list[1:])
            )
            src_ip = f"192.168.{random.randint(1,9)}.{random.randint(1,254)}"
            _process_flow(flow, src_ip=src_ip, raise_alerts=False)

        time.sleep(1)


def _process_flow(flow_features, src_ip="0.0.0.0",
                   force_attack=False, min_packets=0, flow_meta=None,
                   raise_alerts=True):
    """Process one network flow through the model and emit alert if needed."""
    if flow_meta and flow_meta.get('pkt_count', 0) < min_packets:
        return

    STATE['n_flows_seen'] += 1

    if STATE['model'] is None:
        if flow_meta:
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

        # Pad flow features into a sequence of shape (1, seq_len, n_features)
        padded = np.tile(flow_features, (SEQUENCE_LEN, 1))
        # Ensure feature dimension matches model expectation
        if padded.shape[1] < NUM_FEATURES:
            padded = np.pad(padded, ((0,0),(0, NUM_FEATURES - padded.shape[1])))
        elif padded.shape[1] > NUM_FEATURES:
            padded = padded[:, :NUM_FEATURES]
        seq_features = padded[np.newaxis, :, :]  # (1, seq_len, n_features)

        logits = STATE['model'](seq_features, training=False)
        probs  = tf.nn.softmax(logits).numpy()[0]
        pred   = int(np.argmax(probs))
        conf   = float(np.max(probs))
        name   = ATTACK_NAMES.get(pred, 'Unknown')

        # Demo mode: forced attacks should reliably exercise response flow.
        if force_attack and conf < 0.96:
            conf = 0.99

        # Get fuzzy rule
        try:
            anfis = STATE['model'].get_layer('anfis')
            rules = anfis.get_top_rule_for_sample()
            rule  = rules[0] if rules else ""
        except Exception:
            rule = f"IF traffic_pattern IS ANOMALOUS THEN {name}"

        # Real traffic: require non-normal class and sufficient confidence.
        is_attack = force_attack or (pred != 0 and conf >= _ALERT_CONF)
        sev = _severity(conf)
        display_name = name if is_attack else 'Normal'

        if flow_meta:
            _annotate_traffic_detection(
                flow_meta.get('src_ip', src_ip),
                flow_meta.get('dst_ip', ''),
                flow_meta.get('src_port'),
                flow_meta.get('dst_port'),
                display_name,
                conf,
                sev if is_attack else '',
                is_attack,
            )

        if is_attack and raise_alerts:
            STATE['n_attacks_seen'] += 1
            STATE['attack_counts'][name] = \
                STATE['attack_counts'].get(name, 0) + 1
            STATE['alert_count'] += 1

            alert = {
                'id':          STATE['alert_count'],
                'timestamp':   datetime.now().isoformat(),
                'src_ip':      src_ip,
                'attack_type': name,
                'confidence':  round(conf, 4),
                'fuzzy_rule':  rule,
                'severity':    _severity(conf),
                'blocked':     False,
                'dst_ip':      '—',
                'protocol':    '—',
                'length':      None,
                'info':        '',
            }
            if flow_meta:
                alert.update(_alert_fields_from_flow(flow_meta, src_ip))

            # Auto-block high-confidence attacks
            if conf > 0.95 and src_ip not in STATE['blocked_ips']:
                STATE['blocked_ips'][src_ip] = {
                    'blocked_at':    datetime.now().isoformat(),
                    'attack_type':   name,
                    'confidence':    conf,
                    'auto_expires':  True,
                }
                alert['blocked'] = True
                socketio.emit('ip_blocked', {
                    'ip':          src_ip,
                    'attack_type': name,
                    'confidence':  conf,
                })

            STATE['recent_alerts'].appendleft(alert)
            socketio.emit('new_alert', alert)

        # Emit flow stats update every 10 flows
        if STATE['n_flows_seen'] % 10 == 0:
            socketio.emit('flow_stats', {
                'flows_seen':    STATE['n_flows_seen'],
                'attacks_seen':  STATE['n_attacks_seen'],
                'attack_dist':   STATE['attack_counts'],
            })

    except Exception:
        logger.exception("Flow processing failed for source IP %s", src_ip)


def _update_fl_state(data):
    """Update dashboard with new FL round data from training script."""
    if 'round' in data:
        STATE['fl_round'] = data['round']
    if 'trust_scores' in data:
        STATE['trust_scores'] = data['trust_scores']
    if 'quarantined' in data:
        STATE['quarantined'] = data['quarantined']
    if 'drift_nodes' in data:
        STATE['drift_nodes'] = data['drift_nodes']
    if 'avg_f1' in data:
        STATE['fl_history'].append({
            'round':  data.get('round', 0),
            'avg_f1': data.get('avg_f1', 0),
        })

    socketio.emit('fl_update', {
        'round':        STATE['fl_round'],
        'trust_scores': STATE['trust_scores'],
        'quarantined':  STATE['quarantined'],
        'drift_nodes':  STATE['drift_nodes'],
        'avg_f1':       data.get('avg_f1', 0),
    })


def _generate_synthetic_flow(attack_type='BENIGN'):
    """Generate synthetic flow feature vector for demo."""
    np.random.seed(None)
    base = np.random.randn(NUM_FEATURES).astype(np.float32)

    if attack_type in ('DDoS', 'DoS'):
        base[0] *= 5    # high packet rate
        base[1] *= 4    # high byte count
        base[3] *= 3    # high SYN count
    elif attack_type == 'PortScan':
        base[4] *= 6    # many unique destination ports
        base[5] *= 0.1  # very short connections
    elif attack_type in ('Reconnaissance', 'Recon'):
        base[2] *= 3
        base[6] *= 4
    return base


def _severity(confidence):
    if confidence > 0.90: return 'HIGH'
    if confidence > 0.75: return 'MEDIUM'
    return 'LOW'


if __name__ == '__main__':
    print("\n" + "="*55)
    print("  FedAIDA-IDS Real-Time Dashboard")
    print(f"  http://localhost:{DASHBOARD_PORT}")
    print("="*55 + "\n")

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

    socketio.run(
        app,
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=DASHBOARD_DEBUG
    )
