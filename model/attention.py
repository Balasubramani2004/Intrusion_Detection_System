# ============================================================
# model/attention.py
# Bahdanau Attention Mechanism
# Applied after BiLSTM to focus on most suspicious time steps
# ============================================================

import tensorflow as tf


class BahdanauAttention(tf.keras.layers.Layer):
    """
    Bahdanau (additive) attention over BiLSTM output sequence.
    
    Input:  (batch, seq_len, lstm_units * 2)  — BiLSTM output
    Output: (batch, lstm_units * 2)           — context vector
    Also exposes attention_weights for dashboard visualisation.
    """

    def __init__(self, units, **kwargs):
        super().__init__(**kwargs)
        self.units  = units
        self.W1     = tf.keras.layers.Dense(units, use_bias=False)
        self.W2     = tf.keras.layers.Dense(units, use_bias=False)
        self.V      = tf.keras.layers.Dense(1,     use_bias=False)
        self.attention_weights = None

    def call(self, encoder_output, training=False):
        # encoder_output: (batch, seq_len, hidden_size)

        # Score each time step
        # W1 * encoder_output: (batch, seq_len, units)
        score = self.V(tf.nn.tanh(self.W1(encoder_output)))
        # score: (batch, seq_len, 1)

        # Softmax over time dimension
        weights = tf.nn.softmax(score, axis=1)  # (batch, seq_len, 1)
        self.attention_weights = weights         # save for visualisation

        # Context vector — weighted sum of encoder outputs
        context = weights * encoder_output       # (batch, seq_len, hidden)
        context = tf.reduce_sum(context, axis=1) # (batch, hidden)

        return context

    def get_weights_numpy(self):
        """Returns attention weights as numpy for dashboard heatmap."""
        if self.attention_weights is None:
            return None
        return self.attention_weights.numpy()
