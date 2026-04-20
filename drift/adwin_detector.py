"""FedAIDA-IDS: ADWIN Drift Detector (Novelty N3)"""
import os, sys, logging, time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from river.drift import ADWIN
logger = logging.getLogger(__name__)

class DriftMonitor:
    def __init__(self, node_id, delta=0.002, check_interval=50, on_drift_callback=None):
        self.node_id = node_id
        self.detector = ADWIN(delta=delta)
        self.interval = check_interval
        self.callback = on_drift_callback
        self.counter = 0
        self.drift_count = 0
        self.error_history = []
        self.drift_timestamps = []

    def update(self, prediction, true_label):
        error = 1.0 if int(prediction) != int(true_label) else 0.0
        self.error_history.append(error)
        self.detector.update(error)
        self.counter += 1
        if self.detector.drift_detected:
            self.drift_count += 1
            self.drift_timestamps.append(time.time())
            logger.warning(f"[Node {self.node_id}] DRIFT DETECTED #{self.drift_count} at sample {self.counter}")
            self.detector = ADWIN(delta=self.detector.delta)
            if self.callback:
                self.callback(node_id=self.node_id, drift_count=self.drift_count)
            return True
        return False

    def update_batch(self, predictions, true_labels):
        import numpy as np
        preds = predictions if hasattr(predictions, '__iter__') else [predictions]
        labels = true_labels if hasattr(true_labels, '__iter__') else [true_labels]
        return any(self.update(p, t) for p, t in zip(preds, labels))

    def get_recent_error_rate(self, window=100):
        recent = self.error_history[-window:]
        return sum(recent)/len(recent) if recent else 0.0

    def status(self):
        return {"node_id": self.node_id, "samples_seen": self.counter,
                "drift_count": self.drift_count,
                "recent_error_rate": round(self.get_recent_error_rate(), 4)}


class FederatedDriftCoordinator:
    def __init__(self, n_nodes, delta=0.002, check_interval=50):
        self.n_nodes = n_nodes
        self.drift_fl_triggers = 0
        self.monitors = {i: DriftMonitor(i, delta, check_interval, self._on_drift) for i in range(n_nodes)}

    def _on_drift(self, node_id, drift_count):
        self.drift_fl_triggers += 1
        logger.info(f"Coordinator: priority FL round triggered (node={node_id}, trigger#{self.drift_fl_triggers})")

    def update_node(self, node_id, predictions, true_labels):
        return self.monitors[node_id].update_batch(predictions, true_labels)

    def all_status(self):
        return {i: m.status() for i, m in self.monitors.items()}

    def any_drift(self):
        return self.drift_fl_triggers > 0


def simulate_concept_drift(X, y, drift_start_frac=0.7, noise_std=0.5):
    import numpy as np
    X_d = X.copy()
    idx = int(len(X) * drift_start_frac)
    X_d[idx:] += np.random.normal(0, noise_std, X_d[idx:].shape)
    logger.info(f"Drift injected at sample {idx}/{len(X)}")
    return X_d, y, idx
