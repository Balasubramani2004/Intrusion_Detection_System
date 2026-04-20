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
from datetime import datetime
from collections import deque

from config import (
    DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_DEBUG,
    MODEL_DIR, SEQUENCE_LEN, NUM_FEATURES, NUM_CLASSES,
    ATTACK_NAMES
)

app     = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

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
}


# ── Routes ───────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def status():
    return jsonify({
        'monitoring':     STATE['is_monitoring'],
        'model_loaded':   STATE['model'] is not None,
        'fl_round':       STATE['fl_round'],
        'trust_scores':   STATE['trust_scores'],
        'quarantined':    STATE['quarantined'],
        'alert_count':    STATE['alert_count'],
        'flows_seen':     STATE['n_flows_seen'],
        'attacks_seen':   STATE['n_attacks_seen'],
    })


@app.route('/api/alerts')
def get_alerts():
    return jsonify(list(STATE['recent_alerts']))


@app.route('/api/blocked')
def get_blocked():
    return jsonify(STATE['blocked_ips'])


@app.route('/api/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    if ip in STATE['blocked_ips']:
        del STATE['blocked_ips'][ip]
        socketio.emit('ip_unblocked', {'ip': ip})
        return jsonify({'status': 'ok', 'message': f'{ip} unblocked'})
    return jsonify({'status': 'error', 'message': 'IP not found'})


@app.route('/api/unblock_all', methods=['POST'])
def unblock_all():
    STATE['blocked_ips'].clear()
    socketio.emit('all_unblocked', {})
    return jsonify({'status': 'ok'})


@app.route('/api/load_model', methods=['POST'])
def load_model_api():
    data     = request.json or {}
    dataset  = data.get('dataset', 'botiot')
    n_classes = int(data.get('n_classes', 6))

    try:
        from model.fedaida_model import build_fedaida_model
        model     = build_fedaida_model(n_classes=n_classes)
        wpath     = os.path.join(MODEL_DIR, f'fedaida_global_{dataset}.weights.h5')
        if not os.path.exists(wpath):
            wpath = os.path.join(MODEL_DIR, f'fedaida_{dataset}.weights.h5')
        if os.path.exists(wpath):
            model.load_weights(wpath)
            STATE['model'] = model
            msg = f"Model loaded from {wpath}"
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
    data        = request.json or {}
    attack_type = data.get('type', 'PortScan')
    src_ip      = data.get('src_ip', '192.168.1.100')

    flow = _generate_synthetic_flow(attack_type)
    _process_flow(flow, src_ip=src_ip, force_attack=True)
    return jsonify({'status': 'ok', 'message': f'Simulated {attack_type}'})


@app.route('/api/update_fl_round', methods=['POST'])
def update_fl_round():
    """Called by training script to push FL round updates to dashboard."""
    data = request.json or {}
    _update_fl_state(data)
    return jsonify({'status': 'ok'})


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


# ── SocketIO Events ─────────────────────────────────────────

@socketio.on('start_monitoring')
def handle_start_monitoring(data):
    if not STATE['is_monitoring']:
        STATE['is_monitoring'] = True
        thread = threading.Thread(
            target=_monitoring_loop, daemon=True
        )
        thread.start()
        emit('monitoring_status', {'active': True})
        print("[Dashboard] Monitoring started")


@socketio.on('stop_monitoring')
def handle_stop_monitoring(data):
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
    })


# ── Internal Logic ───────────────────────────────────────────

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
            _process_flow(flow, src_ip=src_ip)

        time.sleep(1)


def _process_flow(flow_features, src_ip="0.0.0.0",
                   force_attack=False):
    """Process one network flow through the model and emit alert if needed."""
    STATE['n_flows_seen'] += 1

    if STATE['model'] is None:
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

        # Get fuzzy rule
        try:
            anfis = STATE['model'].get_layer('anfis')
            rules = anfis.get_top_rule_for_sample()
            rule  = rules[0] if rules else ""
        except Exception:
            rule = f"IF traffic_pattern IS ANOMALOUS THEN {name}"

        is_attack = (pred != 0) or force_attack

        if is_attack:
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
            }

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

    except Exception as e:
        pass  # Don't crash dashboard on single flow error


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
    for ds in ['botiot', 'nslkdd', 'cicids']:
        wpath = os.path.join(MODEL_DIR, f'fedaida_global_{ds}.weights.h5')
        if os.path.exists(wpath):
            from model.fedaida_model import build_fedaida_model
            m = build_fedaida_model()
            m.load_weights(wpath)
            STATE['model'] = m
            print(f"[Dashboard] Auto-loaded model: {wpath}")
            break

    socketio.run(
        app,
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=DASHBOARD_DEBUG
    )
