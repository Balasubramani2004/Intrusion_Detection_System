# ============================================================
# evaluation/metrics.py
# Full evaluation suite for FedAIDA-IDS
# Produces all tables and figures needed for the paper
# ============================================================

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report, roc_curve
)
from sklearn.preprocessing import label_binarize
import os, sys, logging
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import RESULTS_DIR, ATTACK_NAMES

logger = logging.getLogger(__name__)


# ── Core Evaluation ──────────────────────────────────────────

def evaluate_model(model, X_test, y_test,
                   class_names=None, save_dir=None, dataset_name=""):
    """
    Full evaluation: accuracy, precision, recall, F1, FPR, AUC.
    Saves confusion matrix and ROC curves.
    Returns dict of all metrics.

    Args:
        model:        trained Keras model
        X_test:       (N, seq_len, n_features)
        y_test:       (N,) integer labels
        class_names:  list of class name strings (optional)
        save_dir:     directory to save plots (optional)
        dataset_name: string label for plot titles (optional)
    """
    import tensorflow as tf

    save_dir = save_dir or os.path.join(RESULTS_DIR, 'plots')
    os.makedirs(save_dir, exist_ok=True)

    logits = model(X_test, training=False)
    probs  = tf.nn.softmax(logits).numpy()
    preds  = np.argmax(probs, axis=1)

    classes = np.unique(np.concatenate([y_test, preds]))
    classes = np.arange(probs.shape[1])   # use all output classes
    n_cls   = len(classes)

    if class_names is None:
        class_names = [ATTACK_NAMES.get(int(c), f"Class_{c}") for c in classes]

    acc  = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, average='macro', zero_division=0)
    rec  = recall_score(y_test, preds,    average='macro', zero_division=0)
    f1   = f1_score(y_test, preds,        average='macro', zero_division=0)

    # False Positive Rate
    classes_present = sorted(np.unique(y_test))
    cm  = confusion_matrix(y_test, preds, labels=classes_present)
    fpr = _compute_fpr(cm)

    # AUC (macro one-vs-rest)
    try:
        y_bin = label_binarize(y_test, classes=classes_present)
        prob_subset = probs[:, classes_present]
        if y_bin.shape[1] < 2:
            auc = 0.0
        else:
            auc = roc_auc_score(y_bin, prob_subset,
                                multi_class='ovr', average='macro')
    except Exception:
        auc = 0.0

    metrics = {
        'dataset':    dataset_name,
        'accuracy':   round(float(acc),  4),
        'precision':  round(float(prec), 4),
        'recall':     round(float(rec),  4),
        'macro_f1':   round(float(f1),   4),
        'f1':         round(float(f1),   4),
        'fpr':        round(float(fpr),  4),
        'auc':        round(float(auc),  4),
    }

    logger.info(f"\n{'='*55}")
    logger.info(f"Results — {dataset_name}")
    logger.info(f"  Accuracy:  {acc:.4f}")
    logger.info(f"  Precision: {prec:.4f}")
    logger.info(f"  Recall:    {rec:.4f}")
    logger.info(f"  F1 Score:  {f1:.4f}")
    logger.info(f"  FPR:       {fpr:.4f}")
    logger.info(f"  AUC:       {auc:.4f}")
    logger.info(f"{'='*55}")

    # Per-class report
    present_names = [class_names[c] for c in classes_present
                     if c < len(class_names)]
    report = classification_report(y_test, preds,
                                   labels=classes_present,
                                   target_names=present_names,
                                   zero_division=0)
    logger.info(f"\n{report}")
    metrics['per_class_report'] = report

    # Save plots
    _plot_confusion_matrix(cm, present_names, dataset_name, save_dir)
    _plot_roc_curves(y_test, probs, classes_present, present_names,
                     dataset_name, save_dir)

    return metrics


# ── Multi-Seed Evaluation ────────────────────────────────────

def multi_seed_eval(model_builder, X_train, y_train, X_test, y_test,
                    n_seeds=5, dataset_name=""):
    """
    Train and evaluate model n_seeds times with different random seeds.
    Reports mean ± std for the paper statistics table.

    Args:
        model_builder: callable () -> Keras model
        X_train, y_train: training data
        X_test, y_test:   test data
        n_seeds:          number of random seeds (default 5)
        dataset_name:     label string for logging

    Returns:
        (mean_f1, std_f1, all_f1_list)
    """
    import tensorflow as tf
    from config import LOCAL_EPOCHS, BATCH_SIZE

    all_f1, all_acc, all_fpr = [], [], []

    for seed in range(n_seeds):
        np.random.seed(seed)
        tf.random.set_seed(seed)

        model = model_builder()
        model.fit(X_train, y_train,
                  epochs=LOCAL_EPOCHS,
                  batch_size=BATCH_SIZE,
                  verbose=0)

        logits = model(X_test, training=False)
        preds  = np.argmax(tf.nn.softmax(logits).numpy(), axis=1)

        f1  = f1_score(y_test, preds, average='macro', zero_division=0)
        acc = accuracy_score(y_test, preds)
        cm  = confusion_matrix(y_test, preds)
        fpr = _compute_fpr(cm)

        all_f1.append(float(f1))
        all_acc.append(float(acc))
        all_fpr.append(float(fpr))
        logger.info(f"  Seed {seed}: F1={f1:.4f}, Acc={acc:.4f}, FPR={fpr:.4f}")

    mean_f1 = float(np.mean(all_f1))
    std_f1  = float(np.std(all_f1))

    logger.info(f"\n[Multi-seed {dataset_name}]")
    logger.info(f"  F1:  {mean_f1:.4f} ± {std_f1:.4f}")
    logger.info(f"  Acc: {np.mean(all_acc):.4f} ± {np.std(all_acc):.4f}")
    logger.info(f"  FPR: {np.mean(all_fpr):.4f} ± {np.std(all_fpr):.4f}")

    return mean_f1, std_f1, all_f1


# ── Ablation Study ───────────────────────────────────────────

def ablation_study(node_seqs, test_data, n_features, n_classes,
                   label_names, save_dir, seq_len=10):
    """
    Ablation study: compare full FedAIDA model against degraded variants.
    Tests Novelty N1 (CNN+BiLSTM vs plain LSTM) and N2 (ANFIS vs Dense).

    Returns dict of results for all variants.
    """
    import tensorflow as tf
    from config import LOCAL_EPOCHS, BATCH_SIZE, LEARNING_RATE, L2_REG, DROPOUT_RATE

    os.makedirs(save_dir, exist_ok=True)
    X_te, y_te = test_data

    variants = {
        'FedAIDA-Full':    _build_full_model,
        'NoANFIS (Dense)': _build_no_anfis,
        'NoBiLSTM (CNN)':  _build_no_bilstm,
        'NoAttn':          _build_no_attention,
    }

    results = {}
    all_f1s, labels = [], []

    X_all = np.vstack([x for x, _ in node_seqs if len(x) > 0])
    y_all = np.hstack([y for _, y in node_seqs if len(y) > 0])

    for variant_name, builder_fn in variants.items():
        logger.info(f"\n  Ablation — {variant_name}")
        try:
            model = builder_fn(seq_len, n_features, n_classes)
            model.fit(X_all, y_all, epochs=LOCAL_EPOCHS, batch_size=BATCH_SIZE, verbose=0)

            logits = model(X_te, training=False)
            preds  = np.argmax(tf.nn.softmax(logits).numpy(), axis=1)
            f1  = float(f1_score(y_te, preds, average='macro', zero_division=0))
            acc = float(accuracy_score(y_te, preds))
            cm  = confusion_matrix(y_te, preds)
            fpr = float(_compute_fpr(cm))

            results[variant_name] = {'f1': round(f1, 4), 'acc': round(acc, 4),
                                     'fpr': round(fpr, 4)}
            all_f1s.append(f1)
            labels.append(variant_name)
            logger.info(f"    F1={f1:.4f} | Acc={acc:.4f} | FPR={fpr:.4f}")
        except Exception as e:
            logger.warning(f"    Variant {variant_name} failed: {e}")
            results[variant_name] = {'f1': 0.0, 'acc': 0.0, 'fpr': 1.0}
            all_f1s.append(0.0)
            labels.append(variant_name)

    # Plot ablation bar chart
    plt.figure(figsize=(10, 5))
    colors = ['#2196F3', '#FF9800', '#9C27B0', '#4CAF50']
    bars = plt.bar(labels, all_f1s, color=colors[:len(labels)], alpha=0.85, edgecolor='black')
    for bar, val in zip(bars, all_f1s):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                 f'{val:.3f}', ha='center', va='bottom', fontsize=11, fontweight='bold')
    plt.ylabel('Macro F1 Score', fontsize=12)
    plt.title('FedAIDA-IDS Ablation Study — Component Contribution', fontsize=13)
    plt.ylim(0, 1.1)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    out = os.path.join(save_dir, 'ablation_study.png')
    plt.savefig(out, dpi=150)
    plt.close()
    logger.info(f"[Plot] Ablation study saved: {out}")

    return results


# ── FL Convergence Plot ──────────────────────────────────────

def plot_fl_convergence(round_history, save_dir=None):
    """
    Plot F1 vs FL round — Figure 1 in paper.

    Args:
        round_history: list of dicts with 'round' and 'f1' keys
                       (as produced by FedAIDASimulation.train())
        save_dir:      directory to save the plot
    """
    save_dir = save_dir or os.path.join(RESULTS_DIR, 'plots')
    os.makedirs(save_dir, exist_ok=True)

    if not round_history:
        logger.warning("plot_fl_convergence: empty round_history, skipping")
        return

    rounds = [r['round'] for r in round_history]
    # Support both 'f1' (train.py key) and 'avg_f1' (legacy key)
    f1s    = [r.get('f1', r.get('avg_f1', 0.0)) for r in round_history]

    plt.figure(figsize=(10, 5))
    plt.plot(rounds, f1s, 'b-o', linewidth=2, markersize=4, label='Macro F1')
    plt.xlabel('FL Round', fontsize=12)
    plt.ylabel('Macro F1 Score', fontsize=12)
    plt.title('FedAIDA-IDS Convergence — F1 vs FL Round', fontsize=13)
    plt.grid(True, alpha=0.3)
    plt.ylim(0, 1.05)
    plt.legend()
    plt.tight_layout()
    path = os.path.join(save_dir, 'fl_convergence.png')
    plt.savefig(path, dpi=150)
    plt.close()
    logger.info(f"[Plot] FL convergence saved: {path}")


# ── Trust Score Plot ─────────────────────────────────────────

def plot_trust_scores(trust_log, save_dir=None, n_nodes=9):
    """
    Plot IRBA trust score evolution per node — Figure 2 in paper.

    Args:
        trust_log:  list of dicts produced by irba.trust_log
                    Each dict: {'trust_scores': {node_id: score}, 'quarantined': [...]}
        save_dir:   directory to save the plot
        n_nodes:    total number of FL nodes
    """
    save_dir = save_dir or os.path.join(RESULTS_DIR, 'plots')
    os.makedirs(save_dir, exist_ok=True)

    if not trust_log:
        logger.warning("plot_trust_scores: empty trust_log, skipping")
        return

    rounds = list(range(1, len(trust_log) + 1))

    # Collect all quarantined node IDs across all rounds
    ever_quarantined = set()
    for entry in trust_log:
        ever_quarantined.update(entry.get('quarantined', []))

    plt.figure(figsize=(12, 5))

    for node_id in range(n_nodes):
        scores = [entry['trust_scores'].get(str(node_id),
                  entry['trust_scores'].get(node_id, 0.5))
                  for entry in trust_log]
        is_byzantine = node_id in ever_quarantined
        color  = 'red' if is_byzantine else 'steelblue'
        alpha  = 0.95 if is_byzantine else 0.65
        lw     = 2.0  if is_byzantine else 1.3
        label  = f"Node {node_id} (Byzantine/Quarantined)" if is_byzantine else f"Node {node_id}"
        plt.plot(rounds, scores, color=color, label=label,
                 alpha=alpha, linewidth=lw)

    plt.axhline(y=0.20, color='darkred', linestyle='--', alpha=0.7,
                label='Quarantine Threshold (0.20)', linewidth=1.5)
    plt.xlabel('FL Round', fontsize=12)
    plt.ylabel('IRBA Trust Score', fontsize=12)
    plt.title('IRBA Node Trust Scores Over FL Rounds', fontsize=13)
    plt.legend(fontsize=7, loc='lower right', ncol=2)
    plt.grid(True, alpha=0.3)
    plt.ylim(0, 1.0)
    plt.tight_layout()
    path = os.path.join(save_dir, 'irba_trust_scores.png')
    plt.savefig(path, dpi=150)
    plt.close()
    logger.info(f"[Plot] Trust scores saved: {path}")


# ── Drift Recovery Plot ──────────────────────────────────────

def plot_drift_recovery(pre_drift_f1, f1_trace, save_dir=None, drift_round=0):
    """
    Plot ADWIN drift detection and F1 recovery — Figure 3 in paper.

    Args:
        pre_drift_f1:  F1 score before drift injection (float)
        f1_trace:      list of F1 scores in batches after drift
        save_dir:      directory to save the plot
        drift_round:   index in f1_trace where drift was injected
    """
    save_dir = save_dir or os.path.join(RESULTS_DIR, 'plots')
    os.makedirs(save_dir, exist_ok=True)

    if not f1_trace:
        logger.warning("plot_drift_recovery: empty f1_trace, skipping")
        return

    steps = list(range(len(f1_trace)))

    plt.figure(figsize=(12, 5))

    # Pre-drift baseline
    plt.axhline(y=pre_drift_f1, color='green', linestyle=':',
                linewidth=1.5, alpha=0.8, label=f'Pre-Drift F1 ({pre_drift_f1:.3f})')

    # Post-drift trace
    plt.plot(steps, f1_trace, 'b-o', linewidth=2, markersize=4,
             label='Post-Drift F1')

    # Mark drift injection point
    if 0 <= drift_round < len(f1_trace):
        plt.axvline(x=drift_round, color='red', linestyle='--',
                    linewidth=2, alpha=0.8, label='Drift Injected')

    plt.xlabel('Batch Step (post-drift)', fontsize=12)
    plt.ylabel('Macro F1 Score', fontsize=12)
    plt.title('ADWIN Drift Detection & Model F1 Recovery', fontsize=13)
    plt.legend(fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.ylim(0, 1.05)
    plt.tight_layout()
    path = os.path.join(save_dir, 'drift_recovery.png')
    plt.savefig(path, dpi=150)
    plt.close()
    logger.info(f"[Plot] Drift recovery saved: {path}")


# ── CSV Export ───────────────────────────────────────────────

def save_metrics_csv(metrics_list, filename="results.csv"):
    """Save list of metric dicts to CSV for paper tables."""
    path = os.path.join(RESULTS_DIR, 'metrics', filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df = pd.DataFrame(metrics_list)
    df.to_csv(path, index=False)
    logger.info(f"[Metrics] Saved to {path}")
    return path


# ── Internal Helpers ─────────────────────────────────────────

def _compute_fpr(cm):
    """Macro-averaged False Positive Rate from confusion matrix."""
    n = cm.shape[0]
    fprs = []
    for i in range(n):
        fp = cm[:, i].sum() - cm[i, i]
        tn = cm.sum() - cm[i, :].sum() - cm[:, i].sum() + cm[i, i]
        fpr_i = fp / (fp + tn + 1e-7)
        fprs.append(fpr_i)
    return float(np.mean(fprs))


def _plot_confusion_matrix(cm, class_names, title, save_dir):
    plt.figure(figsize=(max(8, len(class_names)), max(6, len(class_names) - 1)))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_names, yticklabels=class_names)
    plt.title(f'Confusion Matrix — {title}')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    safe = title.replace(" ", "_").replace("/", "_")
    path = os.path.join(save_dir, f'confusion_matrix_{safe}.png')
    plt.savefig(path, dpi=150)
    plt.close()
    logger.info(f"[Plot] Confusion matrix saved: {path}")


def _plot_roc_curves(y_test, probs, classes, class_names, title, save_dir):
    y_bin = label_binarize(y_test, classes=classes)
    if y_bin.ndim == 1 or y_bin.shape[1] < 2:
        return
    plt.figure(figsize=(10, 8))
    colors = plt.cm.tab10(np.linspace(0, 1, len(classes)))
    for i, (c, name) in enumerate(zip(classes, class_names)):
        if i >= probs.shape[1] or i >= y_bin.shape[1]:
            break
        fpr_, tpr_, _ = roc_curve(y_bin[:, i], probs[:, c])
        try:
            auc_val = roc_auc_score(y_bin[:, i], probs[:, c])
        except Exception:
            auc_val = 0.0
        plt.plot(fpr_, tpr_, color=colors[i],
                 label=f"{name} (AUC={auc_val:.3f})", linewidth=1.8)
    plt.plot([0, 1], [0, 1], 'k--', alpha=0.5)
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title(f'ROC Curves — {title}', fontsize=13)
    plt.legend(loc='lower right', fontsize=9)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    safe = title.replace(" ", "_").replace("/", "_")
    path = os.path.join(save_dir, f'roc_{safe}.png')
    plt.savefig(path, dpi=150)
    plt.close()
    logger.info(f"[Plot] ROC curves saved: {path}")


# ── Ablation Variant Builders ────────────────────────────────

def _build_full_model(seq_len, n_features, n_classes):
    """Full FedAIDA model (same as production)."""
    from model.fedaida_model import build_fedaida_model
    return build_fedaida_model(n_features=n_features,
                                seq_len=seq_len, n_classes=n_classes)


def _build_no_anfis(seq_len, n_features, n_classes):
    """CNN+BiLSTM+Attention but Dense output (no ANFIS)."""
    import tensorflow as tf
    from config import CNN_FILTERS, CNN_KERNEL, LSTM_UNITS, DROPOUT_RATE, LEARNING_RATE, L2_REG
    reg = tf.keras.regularizers.l2(L2_REG)
    inp = tf.keras.Input(shape=(seq_len, n_features))
    x = tf.keras.layers.Conv1D(CNN_FILTERS, CNN_KERNEL, padding='same',
                                activation='relu', kernel_regularizer=reg)(inp)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.Bidirectional(
        tf.keras.layers.LSTM(LSTM_UNITS, return_sequences=False,
                             dropout=DROPOUT_RATE))(x)
    x = tf.keras.layers.Dropout(DROPOUT_RATE)(x)
    out = tf.keras.layers.Dense(n_classes)(x)
    m = tf.keras.Model(inp, out, name='NoANFIS')
    m.compile(optimizer=tf.keras.optimizers.Adam(LEARNING_RATE),
              loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
              metrics=['accuracy'])
    return m


def _build_no_bilstm(seq_len, n_features, n_classes):
    """CNN only (no BiLSTM, no Attention, no ANFIS)."""
    import tensorflow as tf
    from config import CNN_FILTERS, CNN_KERNEL, DROPOUT_RATE, LEARNING_RATE, L2_REG
    reg = tf.keras.regularizers.l2(L2_REG)
    inp = tf.keras.Input(shape=(seq_len, n_features))
    x = tf.keras.layers.Conv1D(CNN_FILTERS, CNN_KERNEL, padding='same',
                                activation='relu', kernel_regularizer=reg)(inp)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.GlobalAveragePooling1D()(x)
    x = tf.keras.layers.Dropout(DROPOUT_RATE)(x)
    out = tf.keras.layers.Dense(n_classes)(x)
    m = tf.keras.Model(inp, out, name='NoBiLSTM')
    m.compile(optimizer=tf.keras.optimizers.Adam(LEARNING_RATE),
              loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
              metrics=['accuracy'])
    return m


def _build_no_attention(seq_len, n_features, n_classes):
    """CNN+BiLSTM with GlobalPool instead of Attention (no ANFIS)."""
    import tensorflow as tf
    from config import CNN_FILTERS, CNN_KERNEL, LSTM_UNITS, DROPOUT_RATE, LEARNING_RATE, L2_REG
    reg = tf.keras.regularizers.l2(L2_REG)
    inp = tf.keras.Input(shape=(seq_len, n_features))
    x = tf.keras.layers.Conv1D(CNN_FILTERS, CNN_KERNEL, padding='same',
                                activation='relu', kernel_regularizer=reg)(inp)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.Bidirectional(
        tf.keras.layers.LSTM(LSTM_UNITS, return_sequences=True,
                             dropout=DROPOUT_RATE))(x)
    x = tf.keras.layers.GlobalAveragePooling1D()(x)
    x = tf.keras.layers.Dropout(DROPOUT_RATE)(x)
    out = tf.keras.layers.Dense(n_classes)(x)
    m = tf.keras.Model(inp, out, name='NoAttn')
    m.compile(optimizer=tf.keras.optimizers.Adam(LEARNING_RATE),
              loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
              metrics=['accuracy'])
    return m
