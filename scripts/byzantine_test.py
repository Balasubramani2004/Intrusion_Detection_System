"""
FedAIDA-IDS — Byzantine Attack Experiment
Tests IRBA against model poisoning.
Run: python scripts/byzantine_test.py
"""
import os, sys, json, logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('Byzantine-Test')


def run_byzantine_experiment(node_seqs, test_data, n_features, n_classes,
                              label_names, seq_len, n_rounds=30,
                              n_byzantine=2, plots_dir='results/plots',
                              metrics_dir='results/metrics'):
    """
    Compare FedAvg vs IRBA under Byzantine attack.
    Key experiment for Novelty N4 in the paper.

    Setup:
      - 9 nodes, first n_byzantine nodes send inverted (poisoned) weights
      - Compare F1 degradation: standard FedAvg vs IRBA

    Expected result:
      - FedAvg F1 drops to ~0.62 under attack
      - IRBA F1 stays at ~0.91 (quarantines malicious nodes within 3 rounds)
    """
    from model.fedaida_model import build_fedaida_model
    from federation.irba import IRBATrustScorer
    from sklearn.metrics import f1_score
    import matplotlib; matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    os.makedirs(plots_dir, exist_ok=True)
    os.makedirs(metrics_dir, exist_ok=True)

    byzantine_nodes = set(range(n_byzantine))
    logger.info(f"Byzantine nodes: {sorted(byzantine_nodes)}")
    logger.info(f"Rounds: {n_rounds} | Nodes: {len(node_seqs)} | Byzantine: {n_byzantine}")

    X_te, y_te = test_data

    # ── Experiment 1: Standard FedAvg (no defence) ───────────
    logger.info("\n[1/2] Standard FedAvg (no Byzantine defence)...")
    fedavg_f1 = []
    global_weights_plain = build_fedaida_model(
        n_features=n_features, seq_len=seq_len, n_classes=n_classes).get_weights()

    for rnd in range(1, n_rounds + 1):
        all_w = []; all_n = []
        for nid, (Xn, yn) in enumerate(node_seqs):
            if len(Xn) < 2: continue
            m = build_fedaida_model(
                n_features=n_features, seq_len=seq_len, n_classes=n_classes)
            m.set_weights(global_weights_plain)
            split = int(0.85 * len(yn))
            m.fit(Xn[:split], yn[:split], epochs=3, batch_size=64, verbose=0)
            w = m.get_weights()
            if nid in byzantine_nodes:
                w = [-wi for wi in w]  # invert weights
            all_w.append((w, len(yn[:split])))

        if not all_w: continue
        total_n = sum(n for _, n in all_w)
        agg = None
        for w, n in all_w:
            wt = n / total_n
            agg = [a + p * wt for a, p in zip(agg, w)] if agg else [p * wt for p in w]
        global_weights_plain = agg

        m_eval = build_fedaida_model(
            n_features=n_features, seq_len=seq_len, n_classes=n_classes)
        m_eval.set_weights(global_weights_plain)
        if len(X_te) > 0:
            preds = np.argmax(m_eval.predict(X_te, verbose=0), axis=1)
            f1 = f1_score(y_te, preds, average='macro', zero_division=0)
            fedavg_f1.append(round(float(f1), 4))
            if rnd % 5 == 0:
                logger.info(f"  FedAvg  Round {rnd:3d} | F1={f1:.4f}")

    # ── Experiment 2: IRBA Defence ────────────────────────────
    logger.info("\n[2/2] IRBA Defence (trust-weighted aggregation)...")
    irba_f1 = []
    irba = IRBATrustScorer(len(node_seqs), n_classes)
    global_weights_irba = build_fedaida_model(
        n_features=n_features, seq_len=seq_len, n_classes=n_classes).get_weights()

    for rnd in range(1, n_rounds + 1):
        all_w = {}; all_n = {}
        for nid, (Xn, yn) in enumerate(node_seqs):
            if len(Xn) < 2: continue
            m = build_fedaida_model(
                n_features=n_features, seq_len=seq_len, n_classes=n_classes)
            m.set_weights(global_weights_irba)
            split = int(0.85 * len(yn))
            m.fit(Xn[:split], yn[:split], epochs=3, batch_size=64, verbose=0)
            w = m.get_weights()
            if nid in byzantine_nodes:
                w = [-wi for wi in w]  # poisoned
            all_w[nid] = w
            all_n[nid] = len(yn[:split])

        # Update trust scores
        for nid, w in all_w.items():
            if w[0] is not None:
                irba.update_trust(nid, w[0], {k: v[0] for k, v in all_w.items()})

        # Trust-weighted aggregate
        agg = irba.aggregate(all_w, all_n)
        if agg is not None:
            global_weights_irba = agg

        m_eval = build_fedaida_model(
            n_features=n_features, seq_len=seq_len, n_classes=n_classes)
        m_eval.set_weights(global_weights_irba)
        if len(X_te) > 0:
            preds = np.argmax(m_eval.predict(X_te, verbose=0), axis=1)
            f1 = f1_score(y_te, preds, average='macro', zero_division=0)
            irba_f1.append(round(float(f1), 4))
            if rnd % 5 == 0:
                ts = irba.get_status()
                logger.info(f"  IRBA    Round {rnd:3d} | F1={f1:.4f} | "
                            f"quarantined={ts['quarantined']}")

    # ── Plot ──────────────────────────────────────────────────
    rounds = list(range(1, len(fedavg_f1) + 1))
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(rounds[:len(fedavg_f1)], fedavg_f1, 'r--o', markersize=4,
            label='FedAvg (No Defence)', linewidth=2)
    ax.plot(rounds[:len(irba_f1)], irba_f1, 'b-o', markersize=4,
            label='IRBA (FedAIDA-IDS)', linewidth=2)
    ax.axhline(y=0.2, color='red', linestyle=':', alpha=0.5, label='Quarantine Threshold')
    ax.set_xlabel('FL Round', fontsize=12)
    ax.set_ylabel('Macro F1 Score', fontsize=12)
    ax.set_title(f'Byzantine Attack: {n_byzantine} Malicious Nodes / {len(node_seqs)} Total\n'
                 f'IRBA vs Standard FedAvg', fontsize=12)
    ax.legend(fontsize=11); ax.grid(alpha=0.3)
    ax.set_ylim(0, 1.05)
    plt.tight_layout()
    out = os.path.join(plots_dir, 'byzantine_experiment.png')
    plt.savefig(out, dpi=150); plt.close()
    logger.info(f"Saved: {out}")

    # ── Summary ───────────────────────────────────────────────
    final_fedavg = fedavg_f1[-1] if fedavg_f1 else 0
    final_irba   = irba_f1[-1]   if irba_f1   else 0
    results = {
        'fedavg_f1_final':  round(final_fedavg, 4),
        'irba_f1_final':    round(final_irba, 4),
        'improvement':      round(final_irba - final_fedavg, 4),
        'quarantined_nodes':irba.get_status()['quarantined'],
        'fedavg_trace':     fedavg_f1,
        'irba_trace':       irba_f1,
    }
    with open(os.path.join(metrics_dir, 'byzantine_results.json'), 'w') as f:
        json.dump(results, f, indent=2)

    logger.info(f"\nByzantine Experiment Results:")
    logger.info(f"  FedAvg final F1:  {final_fedavg:.4f}")
    logger.info(f"  IRBA   final F1:  {final_irba:.4f}")
    logger.info(f"  Improvement:      +{final_irba-final_fedavg:.4f}")
    logger.info(f"  Quarantined:      {irba.get_status()['quarantined']}")
    logger.info(f"  Plot saved:       {out}")
    return results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset',   default='nsl_kdd')
    parser.add_argument('--rounds',    type=int, default=30)
    parser.add_argument('--byzantine', type=int, default=2)
    args = parser.parse_args()

    from data.preprocess import prepare_all
    from config import SEQUENCE_LEN, PLOTS_DIR, METRICS_DIR

    cfg = {'dataset': args.dataset, 'models_dir': 'saved_models'}
    node_seqs, test_data, label_names, scaler, n_features = prepare_all(args.dataset, cfg)
    n_classes = len(label_names)

    run_byzantine_experiment(
        node_seqs, test_data, n_features, n_classes, label_names,
        SEQUENCE_LEN, n_rounds=args.rounds, n_byzantine=args.byzantine,
        plots_dir=PLOTS_DIR, metrics_dir=METRICS_DIR
    )
