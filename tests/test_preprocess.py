import numpy as np

from data.preprocess import create_sequences, partition_non_iid


def test_create_sequences_shapes_and_labels():
    X = np.arange(40, dtype=np.float32).reshape(10, 4)
    y = np.array([0, 1, 1, 2, 2, 3, 3, 4, 4, 0], dtype=np.int32)

    X_seq, y_seq = create_sequences(X, y, seq_len=5)

    assert X_seq.shape == (6, 5, 4)
    assert y_seq.shape == (6,)
    # Label for each sequence is the final element of that window.
    np.testing.assert_array_equal(y_seq, y[4:])


def test_partition_non_iid_preserves_all_samples():
    rng = np.random.default_rng(42)
    X = rng.normal(size=(120, 6)).astype(np.float32)
    y = np.array(([0] * 40) + ([1] * 40) + ([2] * 40), dtype=np.int32)

    partitions = partition_non_iid(X, y, n_nodes=5, num_classes=3, seed=7)

    total_samples = sum(len(node_y) for _, node_y in partitions)
    assert total_samples == len(y)
    assert len(partitions) == 5
