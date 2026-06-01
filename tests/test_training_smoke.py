import os

import numpy as np

from config import LOGS_DIR


def test_federated_simulation_single_round_smoke(monkeypatch):
    # train.py configures a file logger at import time.
    os.makedirs(LOGS_DIR, exist_ok=True)

    import train

    monkeypatch.setattr(train, "LOCAL_EPOCHS", 1)
    monkeypatch.setattr(train, "BATCH_SIZE", 8)

    n_features = 6
    n_classes = 3
    seq_len = 4

    rng = np.random.default_rng(123)
    node_sequences = []
    for _ in range(3):
        X_node = rng.normal(size=(32, seq_len, n_features)).astype(np.float32)
        y_node = rng.integers(0, n_classes, size=32, dtype=np.int32)
        node_sequences.append((X_node, y_node))

    X_te = rng.normal(size=(20, seq_len, n_features)).astype(np.float32)
    y_te = rng.integers(0, n_classes, size=20, dtype=np.int32)

    sim = train.FedAIDASimulation(
        node_sequences=node_sequences,
        test_data=(X_te, y_te),
        n_features=n_features,
        n_classes=n_classes,
        label_names=["A", "B", "C"],
        seq_len=seq_len,
        byzantine_nodes=[],
    )
    metrics = sim.train(n_rounds=1)

    assert len(metrics) == 1
    assert "f1" in metrics[0]
