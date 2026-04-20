# ============================================================
# model/fedaida_model.py
# FedAIDA-IDS Core Model
# Architecture: CNN → BiLSTM → Attention → ANFIS → Softmax
# ============================================================

import tensorflow as tf
import numpy as np
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    NUM_FEATURES, SEQUENCE_LEN, CNN_FILTERS, CNN_KERNEL,
    LSTM_UNITS, ATTENTION_UNITS, ANFIS_RULES, DROPOUT_RATE,
    LEARNING_RATE, L2_REG
)
from model.anfis_layer import ANFISLayer
from model.attention   import BahdanauAttention


def build_fedaida_model(n_features=NUM_FEATURES,
                        seq_len=SEQUENCE_LEN,
                        n_classes=5):
    """
    Build the complete FedAIDA-IDS model.
    
    Input shape: (batch, seq_len, n_features)
    Output:      (batch, n_classes) — logits
    """
    reg = tf.keras.regularizers.l2(L2_REG)

    inputs = tf.keras.Input(
        shape=(seq_len, n_features),
        name='flow_sequence'
    )

    # ── CNN: Extract local feature patterns ───────────────
    x = tf.keras.layers.Conv1D(
        filters=CNN_FILTERS,
        kernel_size=CNN_KERNEL,
        padding='same',
        activation='relu',
        kernel_regularizer=reg,
        name='cnn_features'
    )(inputs)
    x = tf.keras.layers.BatchNormalization(name='cnn_bn')(x)
    x = tf.keras.layers.Dropout(DROPOUT_RATE, name='cnn_drop')(x)

    # Second CNN layer for deeper feature extraction
    x = tf.keras.layers.Conv1D(
        filters=CNN_FILTERS * 2,
        kernel_size=CNN_KERNEL,
        padding='same',
        activation='relu',
        kernel_regularizer=reg,
        name='cnn_features_2'
    )(x)
    x = tf.keras.layers.BatchNormalization(name='cnn_bn_2')(x)

    # ── BiLSTM: Temporal sequence learning ────────────────
    x = tf.keras.layers.Bidirectional(
        tf.keras.layers.LSTM(
            LSTM_UNITS,
            return_sequences=True,   # return all steps for attention
            dropout=DROPOUT_RATE,
            recurrent_dropout=0.1,
            kernel_regularizer=reg,
            name='lstm_inner'
        ),
        name='bilstm'
    )(x)
    # x: (batch, seq_len, LSTM_UNITS * 2)

    # ── Attention: Focus on suspicious flow steps ─────────
    attention = BahdanauAttention(ATTENTION_UNITS, name='attention')
    context   = attention(x)
    # context: (batch, LSTM_UNITS * 2)

    context = tf.keras.layers.Dropout(DROPOUT_RATE, name='attn_drop')(context)

    # ── Dense projection before ANFIS ─────────────────────
    # Project down to NUM_FEATURES for ANFIS input
    projected = tf.keras.layers.Dense(
        NUM_FEATURES,
        activation='tanh',
        kernel_regularizer=reg,
        name='projection'
    )(context)

    # ── ANFIS: Interpretable fuzzy classification ─────────
    anfis = ANFISLayer(
        n_rules=ANFIS_RULES,
        n_features=NUM_FEATURES,
        n_classes=n_classes,
        name='anfis'
    )
    logits = anfis(projected)

    model = tf.keras.Model(inputs=inputs, outputs=logits, name='FedAIDA-IDS')

    model.compile(
        optimizer=tf.keras.optimizers.Adam(LEARNING_RATE),
        loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
        metrics=['accuracy',
                 tf.keras.metrics.SparseTopKCategoricalAccuracy(k=3,
                     name='top3_acc')]
    )

    return model


def get_model_weights(model):
    """Extract weights as list of numpy arrays (for Flower FL)."""
    return [w.numpy() for w in model.trainable_variables]


def set_model_weights(model, weights):
    """Set model weights from list of numpy arrays (from Flower FL)."""
    for var, w in zip(model.trainable_variables, weights):
        var.assign(w)


def predict_with_explanation(model, X_seq, feature_names=None,
                              class_names=None):
    """
    Run inference and return predictions + fuzzy rule explanations.
    Used by dashboard for real-time alert generation.
    """
    logits  = model(X_seq, training=False)
    probs   = tf.nn.softmax(logits).numpy()
    preds   = np.argmax(probs, axis=1)
    confs   = np.max(probs, axis=1)

    # Get ANFIS layer
    anfis_layer = model.get_layer('anfis')

    # Get attention weights for heatmap
    attn_layer  = model.get_layer('attention')
    attn_weights = attn_layer.get_weights_numpy()

    # Get top fired rule per sample
    rules = anfis_layer.get_top_rule_for_sample(
        feature_names=feature_names,
        class_names=class_names
    )

    results = []
    for i in range(len(preds)):
        results.append({
            'prediction':       int(preds[i]),
            'class_name':       class_names[preds[i]] if class_names else str(preds[i]),
            'confidence':       float(confs[i]),
            'probabilities':    probs[i].tolist(),
            'fuzzy_rule':       rules[i] if rules else "",
            'attention_weights': attn_weights[i].flatten().tolist()
                                 if attn_weights is not None else []
        })
    return results


def save_model(model, path):
    """Save model weights to disk."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    model.save_weights(path)
    print(f"[Model] Saved to {path}")


def load_model(path, n_classes=5):
    """Load model weights from disk."""
    model = build_fedaida_model(n_classes=n_classes)
    model.load_weights(path)
    print(f"[Model] Loaded from {path}")
    return model
