# ============================================================
# model/anfis_layer.py
# ANFIS — Adaptive Neuro-Fuzzy Inference System
# Custom TensorFlow layer with 5 ANFIS layers:
#   L1: Fuzzification (Gaussian MFs)
#   L2: Rule firing strength (T-norm)
#   L3: Normalisation
#   L4: Consequent (linear combination)
#   L5: Defuzzification (weighted sum)
# ============================================================

import tensorflow as tf
import numpy as np


class GaussianMembership(tf.keras.layers.Layer):
    """
    Layer 1: Fuzzification
    Converts crisp input features into fuzzy membership values.
    Uses Gaussian MF: exp(-0.5 * ((x - c) / sigma)^2)
    """
    def __init__(self, n_rules, n_features, **kwargs):
        super().__init__(**kwargs)
        self.n_rules    = n_rules
        self.n_features = n_features

    def build(self, input_shape):
        # Learnable centers — initialised uniformly
        self.centers = self.add_weight(
            name='centers',
            shape=(self.n_rules, self.n_features),
            initializer=tf.keras.initializers.RandomUniform(-1.0, 1.0),
            trainable=True
        )
        # Learnable widths — initialised to 1.0
        self.sigmas = self.add_weight(
            name='sigmas',
            shape=(self.n_rules, self.n_features),
            initializer=tf.keras.initializers.Constant(1.0),
            constraint=tf.keras.constraints.NonNeg(),  # sigma > 0
            trainable=True
        )
        super().build(input_shape)

    def call(self, inputs):
        # inputs: (batch, n_features)
        # Expand dims for broadcasting: (batch, 1, n_features)
        x = tf.expand_dims(inputs, axis=1)
        # centers/sigmas: (1, n_rules, n_features)
        c = tf.expand_dims(self.centers, axis=0)
        s = tf.expand_dims(self.sigmas,  axis=0) + 1e-7
        # Gaussian: (batch, n_rules, n_features)
        membership = tf.exp(-0.5 * tf.square((x - c) / s))
        return membership  # (batch, n_rules, n_features)


class ANFISLayer(tf.keras.layers.Layer):
    """
    Complete 5-layer ANFIS as a Keras Layer.
    Input:  (batch, n_features) from Attention output
    Output: (batch, n_classes) classification logits
    
    Also exposes:
      - self.rule_strengths: firing strength per rule per sample
      - self.fuzzy_rules: extracted IF-THEN rule strings
    """

    def __init__(self, n_rules, n_features, n_classes, **kwargs):
        super().__init__(**kwargs)
        self.n_rules    = n_rules
        self.n_features = n_features
        self.n_classes  = n_classes
        self.rule_strengths = None

    def build(self, input_shape):
        # L1 — Gaussian membership functions
        self.gauss = GaussianMembership(self.n_rules, self.n_features)

        # L4 — Consequent parameters (one linear combination per rule per class)
        self.consequent = self.add_weight(
            name='consequent',
            shape=(self.n_rules, self.n_classes),
            initializer='glorot_uniform',
            trainable=True
        )
        # Bias per class
        self.bias = self.add_weight(
            name='bias',
            shape=(self.n_classes,),
            initializer='zeros',
            trainable=True
        )
        super().build(input_shape)

    def call(self, inputs, training=False):
        # ── L1: Fuzzification ─────────────────────────────
        # membership: (batch, n_rules, n_features)
        membership = self.gauss(inputs)

        # ── L2: Rule firing strength (T-norm = product) ───
        # w: (batch, n_rules)
        w = tf.reduce_prod(membership, axis=-1)

        # ── L3: Normalise ─────────────────────────────────
        w_sum = tf.reduce_sum(w, axis=-1, keepdims=True) + 1e-7
        w_norm = w / w_sum  # (batch, n_rules)

        # Store for rule extraction and dashboard visualisation
        self.rule_strengths = w_norm

        # ── L4 + L5: Consequent & Defuzzification ─────────
        # w_norm: (batch, n_rules) × consequent: (n_rules, n_classes)
        # → output: (batch, n_classes)
        output = tf.matmul(w_norm, self.consequent) + self.bias

        return output  # logits

    def extract_rules(self, feature_names=None, class_names=None,
                      top_k=5, threshold=0.1):
        """
        Extract human-readable IF-THEN fuzzy rules from trained weights.
        Returns list of rule strings.
        """
        centers = self.gauss.centers.numpy()  # (n_rules, n_features)
        sigmas  = self.gauss.sigmas.numpy()
        consq   = self.consequent.numpy()     # (n_rules, n_classes)

        if feature_names is None:
            feature_names = [f"feat_{i}" for i in range(self.n_features)]
        if class_names is None:
            class_names = [f"class_{i}" for i in range(self.n_classes)]

        # Linguistic terms based on center value
        def term(center, sigma):
            if center < -0.8:  return "VERY_LOW"
            if center < -0.3:  return "LOW"
            if center <  0.3:  return "MEDIUM"
            if center <  0.8:  return "HIGH"
            return "VERY_HIGH"

        rules = []
        for r in range(self.n_rules):
            # Top contributing features for this rule
            contributions = np.abs(centers[r]) / (sigmas[r] + 1e-7)
            top_feat_idx  = np.argsort(contributions)[::-1][:top_k]

            conditions = []
            for fi in top_feat_idx:
                t = term(centers[r, fi], sigmas[r, fi])
                conditions.append(f"{feature_names[fi]} IS {t}")

            # Predicted class for this rule
            pred_class = np.argmax(consq[r])
            conf       = float(np.max(consq[r]))

            rule_str = (
                f"Rule {r:02d}: IF " +
                " AND ".join(conditions) +
                f" THEN {class_names[pred_class]} "
                f"(strength={conf:.3f})"
            )
            rules.append(rule_str)

        return rules

    def get_top_rule_for_sample(self, feature_names=None, class_names=None):
        """
        Returns the most-fired rule for the last batch as a readable string.
        Call after model.predict() to get explanation.
        """
        if self.rule_strengths is None:
            return "No inference run yet"

        strengths = self.rule_strengths.numpy()  # (batch, n_rules)
        top_rules = np.argmax(strengths, axis=1)  # (batch,)

        all_rules = self.extract_rules(feature_names, class_names)
        return [all_rules[r] for r in top_rules]
