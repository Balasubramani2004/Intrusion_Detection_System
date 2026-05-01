"""
FedAIDA-IDS — Main Training Script
Run this to train the complete system.

Usage:
  python train.py --dataset nsl_kdd --rounds 50 --nodes 9
  python train.py --dataset bot_iot --rounds 30 --byzantine
  python train.py --dataset cicids  --rounds 50 --eval_only
"""
import os, sys, json, logging, argparse, time, warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import numpy as np
import tensorflow as tf
import flwr as fl

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from config import *
from data.preprocess import prepare_all
from model.fedaida_model import build_fedaida_model
from federation.irba import IRBATrustScorer
from federation.client import FedAIDAClient
from drift.adwin_detector import FederatedDriftCoordinator, simulate_concept_drift
from evaluation.metrics import (evaluate_model, ablation_study, plot_fl_convergence,
                                  plot_trust_scores, plot_drift_recovery, multi_seed_eval)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'fedaida_train.log')),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('FedAIDA-Train')


# ═══════════════════════════════════════════════════════════
# FEDERATED SIMULATION USING FLOWER
# ═══════════════════════════════════════════════════════════
class FedAIDASimulation:
    """
    Full federated learning simulation using Flower in-process mode.
    No network required — all nodes simulated on one machine.
    """
    def __init__(self, node_sequences, test_data, n_features, n_classes,
                 label_names, seq_len, byzantine_nodes=None):
        self.node_seqs    = node_sequences
        self.test_data    = test_data
        self.n_features   = n_features
        self.n_classes    = n_classes
        self.label_names  = label_names
        self.seq_len      = seq_len
        self.byzantine    = set(byzantine_nodes or [])
        self.n_nodes      = len(node_sequences)

        # IRBA trust scorer
        self.irba = IRBATrustScorer(self.n_nodes, n_classes)

        # Drift coordinator
        self.drift_coord = FederatedDriftCoordinator(self.n_nodes)

        # Shared global model weights
        self.global_model = build_fedaida_model(
            n_features=n_features, seq_len=seq_len, n_classes=n_classes)
        self.global_weights = self.global_model.get_weights()

        # Metrics tracking
        self.round_metrics = []
        self.best_f1 = 0.0

    def _get_val_data(self, node_id):
        """Get a small validation set from test data for IRBA coverage scoring."""
        X_te, y_te = self.test_data
        if len(X_te) == 0:
            return np.empty((0, self.seq_len, self.n_features)), np.empty(0)
        # Sample 200 per class max
        idx = []
        for c in range(self.n_classes):
            c_idx = np.where(y_te == c)[0]
            if len(c_idx) > 0:
                idx.extend(c_idx[:min(40, len(c_idx))].tolist())
        idx = np.array(idx)
        np.random.shuffle(idx)
        return X_te[idx], y_te[idx]

    def train_round(self, round_num):
        """Execute one FL round: local train → IRBA aggregate."""
        logger.info(f"\n{'='*60}")
        logger.info(f"FL Round {round_num}/{FL_ROUNDS}")

        all_weights = {}
        all_n_samples = {}
        all_losses = []
        active_nodes = [i for i in range(self.n_nodes) if i not in self.irba.quarantined]

        # Sample subset of nodes (FRACTION_FIT)
        n_sample = max(MIN_FIT_CLIENTS, int(len(active_nodes) * FRACTION_FIT))
        selected = np.random.choice(active_nodes, min(n_sample, len(active_nodes)), replace=False)

        for node_id in selected:
            X_node, y_node = self.node_seqs[node_id]
            if len(X_node) < 2:
                continue

            # Local model
            local_model = build_fedaida_model(
                n_features=self.n_features, seq_len=self.seq_len, n_classes=self.n_classes)
            local_model.set_weights(self.global_weights)

            # Split local train/val
            split = int(0.85 * len(y_node))
            X_tr, y_tr = X_node[:split], y_node[:split]
            X_vl, y_vl = X_node[split:], y_node[split:]

            if len(X_tr) == 0:
                continue

            # Local training
            history = local_model.fit(
                X_tr, y_tr,
                epochs=LOCAL_EPOCHS, batch_size=BATCH_SIZE,
                validation_data=(X_vl, y_vl) if len(X_vl) > 0 else None,
                verbose=0
            )
            loss = history.history['loss'][-1]
            all_losses.append(loss)

            # Drift check on val set
            if len(X_vl) > 0:
                preds_val = np.argmax(local_model.predict(X_vl, verbose=0), axis=1)
                self.drift_coord.update_node(node_id, preds_val, y_vl)

            # Poisoning simulation for byzantine nodes
            weights = local_model.get_weights()
            if node_id in self.byzantine:
                weights = [-w for w in weights]  # invert for Byzantine attack
                logger.debug(f"  Node {node_id}: sending POISONED weights")

            all_weights[node_id]   = weights
            all_n_samples[node_id] = len(y_tr)

            # IRBA: update trust using first weight matrix as update vector
            if weights and weights[0] is not None:
                # Update coverage score
                val_X_irba, val_y_irba = self._get_val_data(node_id)
                if len(val_X_irba) > 0:
                    def eval_fn(X):
                        return np.argmax(local_model.predict(X, verbose=0), axis=1)
                    self.irba.update_coverage(node_id, eval_fn, val_X_irba, val_y_irba)
                self.irba.update_trust(
                    node_id, weights[0], {k: v[0] for k,v in all_weights.items() if v}
                )

        if not all_weights:
            logger.warning(f"Round {round_num}: no valid updates")
            return

        # IRBA aggregation
        new_weights = self.irba.aggregate(all_weights, all_n_samples)
        if new_weights is not None:
            self.global_weights = new_weights
            self.global_model.set_weights(self.global_weights)

        # Evaluate global model
        X_te, y_te = self.test_data
        if len(X_te) > 0:
            loss_te, acc_te = self.global_model.evaluate(X_te, y_te, verbose=0)
            from sklearn.metrics import f1_score
            preds_te = np.argmax(self.global_model.predict(X_te, verbose=0), axis=1)
            f1 = f1_score(y_te, preds_te, average='macro', zero_division=0)
        else:
            loss_te, acc_te, f1 = 0.0, 0.0, 0.0

        irba_status = self.irba.get_status()
        round_result = {
            'round': round_num,
            'loss': round(float(np.mean(all_losses)) if all_losses else 0.0, 4),
            'test_loss': round(float(loss_te), 4),
            'accuracy': round(float(acc_te), 4),
            'f1': round(float(f1), 4),
            'active_nodes': irba_status['active_nodes'],
            'quarantined': irba_status['quarantined'],
            'trust_scores': irba_status['trust_scores'],
        }
        self.round_metrics.append(round_result)

        if f1 > self.best_f1:
            self.best_f1 = f1
            self.global_model.save_weights(
                os.path.join(MODELS_DIR, 'best_global_model.weights.h5'))

        logger.info(f"Round {round_num:3d} | F1={f1:.4f} | Acc={acc_te:.4f} | "
                    f"Active={len(irba_status['active_nodes'])}/{self.n_nodes} | "
                    f"Quarantined={irba_status['quarantined']}")

    def train(self, n_rounds=FL_ROUNDS):
        """Run full FL training."""
        logger.info(f"\nStarting FedAIDA-IDS Federated Training")
        logger.info(f"  Nodes: {self.n_nodes} | Rounds: {n_rounds} | "
                    f"Byzantine: {sorted(self.byzantine)}")

        for rnd in range(1, n_rounds + 1):
            self.train_round(rnd)

        # Save everything
        self._save_results()
        return self.round_metrics

    def _save_results(self):
        os.makedirs(MODELS_DIR, exist_ok=True)
        os.makedirs(METRICS_DIR, exist_ok=True)

        # Save metrics
        metrics_path = os.path.join(METRICS_DIR, 'fl_round_metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(self.round_metrics, f, indent=2)

        # Save IRBA log
        self.irba.save_log(os.path.join(METRICS_DIR, 'irba_trust_log.json'))

        # Save final model
        self.global_model.save_weights(
            os.path.join(MODELS_DIR, 'final_global_model.weights.h5'))
        logger.info(f"Results saved to {METRICS_DIR}")
        logger.info(f"Best F1: {self.best_f1:.4f}")


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description='FedAIDA-IDS Training')
    parser.add_argument('--dataset',    default='nsl_kdd',
                        choices=['nsl_kdd','cicids','bot_iot'])
    parser.add_argument('--rounds',     type=int,  default=FL_ROUNDS)
    parser.add_argument('--nodes',      type=int,  default=NUM_NODES)
    parser.add_argument('--epochs',     type=int,  default=LOCAL_EPOCHS)
    parser.add_argument('--centralized', action='store_true',
                        help='Run centralized (non-federated) baseline training')
    parser.add_argument('--byzantine',  action='store_true',
                        help='Simulate Byzantine attack (first 2 nodes)')
    parser.add_argument('--drift_test', action='store_true',
                        help='Run drift injection experiment')
    parser.add_argument('--ablation',   action='store_true',
                        help='Run ablation study')
    parser.add_argument('--multi_seed', action='store_true',
                        help='Run 5-seed statistical evaluation')
    parser.add_argument('--eval_only',  action='store_true',
                        help='Skip training, only evaluate saved model')
    args = parser.parse_args()

    # Create output dirs
    for d in [RESULTS_DIR, PLOTS_DIR, METRICS_DIR, MODELS_DIR, LOGS_DIR]:
        os.makedirs(d, exist_ok=True)

    logger.info("=" * 60)
    logger.info("FedAIDA-IDS: Federated Self-Learning Neuro-Fuzzy IDS")
    logger.info("=" * 60)
    logger.info(f"Dataset: {args.dataset} | Rounds: {args.rounds} | "
                f"Nodes: {args.nodes} | Byzantine: {args.byzantine}")

    # ── Step 1: Load & prepare data ─────────────────────────
    logger.info("\n[1/5] Loading and preprocessing dataset...")
    cfg = {'dataset': args.dataset, 'models_dir': MODELS_DIR}
    node_seqs, test_data, label_names, scaler, n_features = prepare_all(
        args.dataset, cfg)
    n_classes = len(label_names)

    logger.info(f"n_features={n_features} | n_classes={n_classes} | "
                f"seq_len={SEQUENCE_LEN} | label_names={label_names}")

    if args.centralized:
        logger.info("\n[CENTRALIZED BASELINE] Training on pooled data...")
        X_train_all = np.vstack([x for x, _ in node_seqs if len(x) > 0])
        y_train_all = np.hstack([y for _, y in node_seqs if len(y) > 0])
        model = build_fedaida_model(n_features=n_features, seq_len=SEQUENCE_LEN, n_classes=n_classes)
        model.fit(X_train_all, y_train_all, epochs=MAX_EPOCHS, batch_size=BATCH_SIZE, verbose=1)
        X_te, y_te = test_data
        if len(X_te) > 0:
            metrics = evaluate_model(
                model, X_te, y_te,
                class_names=label_names,
                save_dir=PLOTS_DIR,
                dataset_name=f"{args.dataset}_centralized",
            )
            with open(os.path.join(METRICS_DIR, 'centralized_metrics.json'), 'w') as f:
                json.dump(metrics, f, indent=2)
        model.save_weights(os.path.join(MODELS_DIR, f'centralized_{args.dataset}.weights.h5'))
        logger.info("[CENTRALIZED BASELINE] Done.")
        return

    if args.eval_only:
        logger.info("\n[EVAL ONLY] Loading saved model...")
        model = build_fedaida_model(n_features=n_features, seq_len=SEQUENCE_LEN, n_classes=n_classes)
        weights_path = os.path.join(MODELS_DIR, 'best_global_model.weights.h5')
        if os.path.exists(weights_path):
            model.load_weights(weights_path)
            X_te, y_te = test_data
            metrics = evaluate_model(model, X_te, y_te, label_names,
                                     PLOTS_DIR, prefix='eval_')
            print(json.dumps(metrics, indent=2))
        else:
            logger.error(f"No saved model at {weights_path}")
        return

    # ── Step 2: Byzantine configuration ─────────────────────
    byzantine_nodes = []
    if args.byzantine:
        byzantine_nodes = list(range(NUM_BYZANTINE_NODES))
        logger.info(f"\n[BYZANTINE SIMULATION] Nodes {byzantine_nodes} will send poisoned weights")

    # ── Step 3: Federated Training ───────────────────────────
    logger.info("\n[2/5] Starting Federated Training...")
    sim = FedAIDASimulation(
        node_seqs, test_data, n_features, n_classes,
        label_names, SEQUENCE_LEN, byzantine_nodes=byzantine_nodes
    )
    round_metrics = sim.train(n_rounds=args.rounds)

    # ── Step 4: Final Evaluation ─────────────────────────────
    logger.info("\n[3/5] Final Evaluation...")
    X_te, y_te = test_data
    if len(X_te) > 0:
        final_metrics = evaluate_model(
            sim.global_model, X_te, y_te,
            class_names=label_names,
            save_dir=PLOTS_DIR,
            dataset_name=args.dataset
        )
        with open(os.path.join(METRICS_DIR, 'final_metrics.json'), 'w') as f:
            json.dump(final_metrics, f, indent=2)
        logger.info(f"Final F1={final_metrics['macro_f1']} | "
                    f"FPR={final_metrics['fpr']}")

    # ── Step 5: Paper Figures ────────────────────────────────
    logger.info("\n[4/5] Generating paper figures...")
    plot_fl_convergence(round_metrics, PLOTS_DIR)
    if sim.irba.trust_log:
        plot_trust_scores(sim.irba.trust_log, PLOTS_DIR, n_nodes=args.nodes)

    # ── Step 6: Optional Experiments ─────────────────────────
    if args.ablation:
        logger.info("\n[5/5] Running Ablation Study...")
        ablation_results = ablation_study(
            node_seqs, test_data, n_features, n_classes,
            label_names, PLOTS_DIR, seq_len=SEQUENCE_LEN
        )
        with open(os.path.join(METRICS_DIR, 'ablation_results.json'), 'w') as f:
            json.dump(ablation_results, f, indent=2)
        logger.info("Ablation results saved")

    if args.drift_test:
        logger.info("\nRunning Drift Detection Experiment...")
        # Use first node's data for drift experiment
        X_node, y_node = node_seqs[0]
        if len(X_node) > 20:
            X_drift, y_drift, drift_idx = simulate_concept_drift(X_node, y_node)
            drift_model = build_fedaida_model(
                n_features=n_features, seq_len=SEQUENCE_LEN, n_classes=n_classes
            )
            drift_model.set_weights(sim.global_weights)
            monitor = sim.drift_coord.monitors[0]

            # Evaluate baseline on pre-drift segment
            from sklearn.metrics import f1_score as sk_f1
            pre_end = max(int(drift_idx), 1)
            X_pre, y_pre = X_drift[:pre_end], y_drift[:pre_end]
            X_post, y_post = X_drift[pre_end:], y_drift[pre_end:]
            if len(X_pre) > 0:
                preds_pre = np.argmax(drift_model.predict(X_pre, verbose=0), axis=1)
                pre_f1 = float(sk_f1(y_pre, preds_pre, average="macro", zero_division=0))
            else:
                pre_f1 = float(final_metrics.get("macro_f1", 0.0)) if len(X_te) > 0 else 0.0

            # Simulate adaptation in FL-like rounds: train briefly on post-drift data
            drift_f1_trace = []
            recovery_round = None
            n_rounds_adapt = max(1, int(DRIFT_FL_ROUNDS))
            # Use a small rolling window to emulate local streaming
            step = max(10, min(200, len(y_post) // max(1, n_rounds_adapt)))
            for r in range(1, n_rounds_adapt + 1):
                start = (r - 1) * step
                end = min(start + step, len(y_post))
                if start >= end:
                    break
                X_batch, y_batch = X_post[start:end], y_post[start:end]

                # ADWIN update on error stream
                preds_b = np.argmax(drift_model.predict(X_batch, verbose=0), axis=1)
                drift_now = bool(monitor.update_batch(preds_b, y_batch))
                if drift_now:
                    # Re-learn fuzzy rules (ANFIS) quickly
                    try:
                        anfis = drift_model.get_layer("anfis")
                        for w in anfis.trainable_variables:
                            w.assign(tf.random.normal(w.shape, stddev=0.1))
                    except Exception:
                        pass

                # One short adaptation epoch on post-drift batch
                drift_model.fit(X_batch, y_batch, epochs=1, batch_size=BATCH_SIZE, verbose=0)

                # Evaluate on a held-out slice of post-drift data
                eval_end = min(len(y_post), end + step)
                X_eval, y_eval = X_post[end:eval_end], y_post[end:eval_end]
                if len(X_eval) == 0:
                    X_eval, y_eval = X_batch, y_batch
                preds_eval = np.argmax(drift_model.predict(X_eval, verbose=0), axis=1)
                f1_r = float(sk_f1(y_eval, preds_eval, average="macro", zero_division=0))
                drift_f1_trace.append(f1_r)

                # Recovery: within 0.02 absolute of pre-drift F1
                if recovery_round is None and f1_r >= (pre_f1 - 0.02):
                    recovery_round = r

            plot_drift_recovery(pre_f1, drift_f1_trace, PLOTS_DIR, drift_round=0)
            drift_metrics = {
                "pre_drift_f1": round(pre_f1, 4),
                "post_drift_f1_trace": [round(float(x), 4) for x in drift_f1_trace],
                "recovery_round": recovery_round,
                "target_recovery_rounds": 4,
            }
            with open(os.path.join(METRICS_DIR, "drift_recovery_metrics.json"), "w") as f:
                json.dump(drift_metrics, f, indent=2)
            logger.info(f"Drift experiment complete | recovery_round={recovery_round}")

    if args.multi_seed:
        logger.info("\nRunning Multi-Seed Evaluation (5 seeds)...")
        X_tr_all = np.vstack([x for x, _ in node_seqs])
        y_tr_all = np.hstack([y for _, y in node_seqs])
        def model_builder():
            return build_fedaida_model(
                n_features=n_features, seq_len=SEQUENCE_LEN, n_classes=n_classes)
        mean_f1, std_f1, all_f1 = multi_seed_eval(
            model_builder, X_tr_all, y_tr_all,
            X_te, y_te, n_seeds=NUM_SEEDS
        )
        seed_results = {'mean_f1': round(mean_f1, 4), 'std_f1': round(std_f1, 4),
                        'all_f1': all_f1}
        with open(os.path.join(METRICS_DIR, 'multi_seed_results.json'), 'w') as f:
            json.dump(seed_results, f, indent=2)
        logger.info(f"Multi-seed F1: {mean_f1:.4f} ± {std_f1:.4f}")

    logger.info("\n" + "="*60)
    logger.info("Training Complete!")
    logger.info(f"  Best F1:     {sim.best_f1:.4f}")
    logger.info(f"  Plots:       {PLOTS_DIR}")
    logger.info(f"  Metrics:     {METRICS_DIR}")
    logger.info(f"  Model:       {MODELS_DIR}/best_global_model.weights.h5")
    logger.info(f"  Dashboard:   python dashboard/app.py")
    logger.info("="*60)


if __name__ == '__main__':
    main()
