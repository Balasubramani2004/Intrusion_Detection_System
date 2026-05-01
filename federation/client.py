# ============================================================
# federation/client.py
# Flower Federated Learning Client
# Each IoT node runs this — trains locally, shares weights only
# Includes ADWIN drift detection (NOVELTY 3)
# ============================================================

import flwr as fl
import numpy as np
import tensorflow as tf
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import LOCAL_EPOCHS, BATCH_SIZE, SEQUENCE_LEN
from model.fedaida_model import build_fedaida_model, get_model_weights, set_model_weights
from data.preprocess import create_sequences as create_sequence_data
from drift.adwin_detector import DriftMonitor as ADWINDriftDetector


class FedAIDAClient(fl.client.NumPyClient):
    """
    Federated Learning client for one IoT network node.
    
    Responsibilities:
    - Train local CNN+BiLSTM+ANFIS model on node's data
    - Detect concept drift with ADWIN
    - Share only model weights (never raw data)
    """

    def __init__(self, node_id, X_train, y_train, X_val, y_val,
                 n_classes=5, seq_len=SEQUENCE_LEN):
        self.node_id   = node_id
        self.n_classes = n_classes
        self.seq_len   = seq_len

        # Create sequential data for BiLSTM
        self.X_train, self.y_train = create_sequence_data(X_train, y_train, seq_len)
        self.X_val,   self.y_val   = create_sequence_data(X_val,   y_val,   seq_len)

        # Build local model
        self.model = build_fedaida_model(
            n_features=X_train.shape[1],
            seq_len=seq_len,
            n_classes=n_classes
        )

        # ADWIN drift detector (NOVELTY 3)
        self.drift_detector = ADWINDriftDetector(node_id=node_id)
        self.drift_count    = 0

        print(f"  [Client {node_id}] Initialised | "
              f"Train: {len(self.X_train)} | Val: {len(self.X_val)}")

    # ── Flower Protocol ──────────────────────────────────────

    def get_parameters(self, config):
        """Return current local model weights."""
        return get_model_weights(self.model)

    def fit(self, parameters, config):
        """
        Receive global weights → train locally → return updated weights.
        Also checks for concept drift and adapts if needed.
        """
        # Set global model weights
        set_model_weights(self.model, parameters)

        # ── Local training ────────────────────────────────
        history = self.model.fit(
            self.X_train, self.y_train,
            epochs=LOCAL_EPOCHS,
            batch_size=BATCH_SIZE,
            validation_data=(self.X_val, self.y_val),
            verbose=0
        )

        # ── Post-training drift update (ADWIN on real error stream) ───────
        val_loss = float(history.history.get('val_loss', [0.0])[-1])
        drift_detected = False
        coverage_score = None
        if len(self.X_val) > 0:
            logits_val = self.model(self.X_val, training=False).numpy()
            preds_val = np.argmax(logits_val, axis=1)
            # Feed per-sample 0/1 error into ADWIN
            drift_detected = bool(self.drift_detector.update_batch(preds_val, self.y_val))
            if drift_detected:
                self.drift_count += 1
                print(f"  [Client {self.node_id}] ADWIN drift detected — resetting ANFIS")
                self._reset_anfis_weights()

            # IDS-aware coverage: fraction of classes detected with ≥0.5 accuracy.
            try:
                classes = np.arange(self.n_classes)
                detected = 0
                for c in classes:
                    idx = np.where(self.y_val == c)[0]
                    if len(idx) == 0:
                        continue
                    acc_c = float(np.mean(preds_val[idx] == c))
                    if acc_c >= 0.5:
                        detected += 1
                coverage_score = detected / float(self.n_classes)
            except Exception:
                coverage_score = None

        train_f1 = self._compute_f1(self.X_train, self.y_train)

        print(f"  [Client {self.node_id}] "
              f"loss={val_loss:.4f} | f1={train_f1:.4f} | "
              f"drift={drift_detected}")

        return (
            get_model_weights(self.model),
            len(self.X_train),
            {
                'node_id':        self.node_id,
                'val_loss':       float(val_loss),
                'f1':             float(train_f1),
                'drift_detected': int(drift_detected),
                'drift_count':    self.drift_count,
                'coverage_score': float(coverage_score) if coverage_score is not None else None,
            }
        )

    def evaluate(self, parameters, config):
        """Evaluate global model on local validation data."""
        set_model_weights(self.model, parameters)
        loss, acc, _ = self.model.evaluate(
            self.X_val, self.y_val, verbose=0
        )
        f1 = self._compute_f1(self.X_val, self.y_val)
        return (
            float(loss),
            len(self.X_val),
            {'accuracy': float(acc), 'f1': float(f1),
             'node_id': self.node_id}
        )

    # ── Helpers ──────────────────────────────────────────────

    def _compute_f1(self, X, y):
        from sklearn.metrics import f1_score
        logits = self.model(X, training=False)
        preds  = np.argmax(logits.numpy(), axis=1)
        return f1_score(y, preds, average='macro', zero_division=0)

    def _check_drift(self):
        return self.drift_detector.is_drifting()

    def _reset_anfis_weights(self):
        """
        Reset only the ANFIS layer weights on concept drift.
        Keeps CNN+BiLSTM knowledge, re-learns fuzzy rules.
        """
        try:
            anfis = self.model.get_layer('anfis')
            for w in anfis.trainable_variables:
                w.assign(tf.random.normal(w.shape, stddev=0.1))
        except Exception as e:
            print(f"  [Client {self.node_id}] ANFIS reset error: {e}")


def create_clients(partitions, n_classes=5):
    """
    Create one FedAIDAClient per data partition.
    
    Args:
        partitions: list of (X_train, y_train) from partitioner
        n_classes: number of attack classes
    
    Returns:
        list of FedAIDAClient
    """
    from sklearn.model_selection import train_test_split

    clients = []
    for i, (X, y) in enumerate(partitions):
        if len(X) < 20:
            print(f"  [Warning] Node {i} has too few samples ({len(X)}), skipping")
            continue
        X_tr, X_val, y_tr, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        client = FedAIDAClient(
            node_id=i,
            X_train=X_tr, y_train=y_tr,
            X_val=X_val,   y_val=y_val,
            n_classes=n_classes
        )
        clients.append(client)

    print(f"[Federation] Created {len(clients)} clients")
    return clients
