# FedAIDA-IDS — Complete Codebase Analysis & Build Plan

## 📋 What the Document Requires (6 Objectives)

| # | Objective | Description |
|---|---|---|
| **O1** | Temporal Deep Feature Extraction | CNN+BiLSTM+Attention pipeline for multi-flow attack sequences |
| **O2** | Interpretable Fuzzy Classification | ANFIS producing human-readable IF-THEN rules per decision |
| **O3** | Self-Adaptive Drift Detection | ADWIN at each node — auto-detects evolving attacks |
| **O4** | Byzantine Poisoning Defence | IRBA trust scoring — quarantine compromised nodes |
| **O5** | Federated Privacy Preservation | FedAvg — only model weights shared, never raw data |
| **O6** | Real-World IoT Deployment | NSL-KDD, CICIDS2017, Bot-IoT + live college network test |

---

## Bugs Found

### BUG 1 — config.py missing keys
app.py imports DASHBOARD_DEBUG, MODEL_DIR (vs MODELS_DIR), ATTACK_NAMES, NUM_CLASSES — none exist in config.py.

### BUG 2 — federation/client.py broken imports
from preprocessing.partitioner import create_sequence_data  # module does not exist
from drift.adwin_detector import ADWINDriftDetector          # class is named DriftMonitor

### BUG 3 — build_fedaida_model arg order wrong in train.py
train.py calls build_fedaida_model(seq_len, n_features, n_classes)
but signature is build_fedaida_model(n_features, seq_len, n_classes)

### BUG 4 — evaluation/metrics.py API mismatches with train.py
- evaluate_model arg order differs
- plot_fl_convergence reads r['avg_f1'] but data stores r['f1']
- plot_trust_scores, plot_drift_recovery signatures completely different
- ablation_study() and multi_seed_eval() are called but missing

### BUG 5 — capture/live_capture.py missing entirely
