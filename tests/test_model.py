import tensorflow as tf

from model.fedaida_model import build_fedaida_model


def test_build_fedaida_model_output_shape():
    model = build_fedaida_model(n_features=8, seq_len=6, n_classes=5)
    x = tf.random.normal((3, 6, 8))
    logits = model(x, training=False)
    assert logits.shape == (3, 5)
