# FedAIDA-IDS — Complete Project Report

**Project:** Federated Self-Learning Neuro-Fuzzy Intrusion Detection System for IoT Networks  
**Team:** Balasubramani M | Guna B V | Sinchana B G  
**Guide:** Dr. Pankaja  
**Institution:** Cambridge Institute of Technology, Bengaluru  
**Target publication:** Future Generation Computer Systems (Elsevier, IF 7.5)  
**Repository:** Intrusion Detection System (FedAIDA-IDS)  
**Report date:** June 2026 (updated)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement and Objectives](#2-problem-statement-and-objectives)
3. [Novelty Contributions](#3-novelty-contributions)
4. [System Architecture](#4-system-architecture)
5. [Datasets](#5-datasets)
6. [Data Preprocessing Pipeline](#6-data-preprocessing-pipeline)
7. [Machine Learning Model](#7-machine-learning-model)
8. [Federated Learning Framework](#8-federated-learning-framework)
9. [IRBA Byzantine Defence](#9-irba-byzantine-defence)
10. [ADWIN Concept Drift Detection](#10-adwin-concept-drift-detection)
11. [Real-Time Deployment and LAN Scan Detection](#11-real-time-deployment-and-lan-scan-detection)
12. [Dashboard and APIs](#12-dashboard-and-apis)
13. [Training Pipeline and Commands](#13-training-pipeline-and-commands)
14. [Evaluation Metrics and Results](#14-evaluation-metrics-and-results)
15. [Outputs and Artifacts](#15-outputs-and-artifacts)
16. [Technology Stack](#16-technology-stack)
17. [Testing and CI](#17-testing-and-ci)
18. [Limitations and Future Work](#18-limitations-and-future-work)
19. [How to Run (Quick Reference)](#19-how-to-run-quick-reference)

---

## 1. Executive Summary

FedAIDA-IDS is an end-to-end intrusion detection system that combines **deep learning** (CNN + BiLSTM + attention), **interpretable fuzzy logic** (ANFIS), **federated learning** (Flower, 9 IoT nodes), **Byzantine-resistant aggregation** (IRBA), and **online drift adaptation** (ADWIN). It is trained on benchmark IDS datasets (NSL-KDD, CICIDS2018, Bot-IoT) and deployed through a **real-time Flask/SocketIO dashboard** with **Windows Wi-Fi capture** (tshark) and **LAN-wide port-scan / nmap detection** on the same college network.

---

## 2. Problem Statement and Objectives

| Objective | Description | Implementation |
|-----------|-------------|----------------|
| **O1** | Temporal deep feature extraction from network flows | CNN → BiLSTM → Bahdanau attention |
| **O2** | Interpretable attack classification | ANFIS layer with IF-THEN fuzzy rules |
| **O3** | Self-adaptive learning under concept drift | ADWIN per FL node (River library) |
| **O4** | Byzantine poisoning defence in federation | IRBA trust-weighted aggregation |
| **O5** | Privacy-preserving training | Federated learning — only weights shared |
| **O6** | Real-world IoT / Wi-Fi validation | Live capture + LAN scan heuristics + dashboard |

---

## 3. Novelty Contributions

| ID | Claim | Module |
|----|-------|--------|
| **N1** | CNN+BiLSTM+Attention as FL local learner | `model/fedaida_model.py` |
| **N2** | ANFIS interpretable fuzzy rules per decision | `model/anfis_layer.py` |
| **N3** | ADWIN self-learning drift detection | `drift/adwin_detector.py` |
| **N4** | IRBA Byzantine poisoning defence | `federation/irba.py` |
| **N5** | Evaluation on modern IoT datasets | NSL-KDD, CICIDS2018, Bot-IoT |

---

## 4. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TRAINING (Offline)                               │
│  Datasets → Preprocess → SMOTE → Non-IID partition → Sequences (10×41)   │
│       → 9 FL nodes → Local train (5 epochs) → IRBA aggregate → Global    │
│       → ADWIN drift → Evaluate → results/plots + saved_models            │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      INFERENCE (Real-Time / Wi-Fi)                       │
│  Windows tshark → capture/incoming/*.pcapng → TsharkIngest (WSL)         │
│       → LiveCapture (Scapy) → Flow features → FedAIDA model (optional)   │
│       → ScanTracker + ArpScanTracker → Alerts on dashboard               │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key modules:**

| Directory | Role |
|-----------|------|
| `config.py` | All hyperparameters |
| `train.py` | Main training + FL simulation |
| `data/preprocess.py` | Load, SMOTE, partition, sequences |
| `model/` | FedAIDA neural + fuzzy model |
| `federation/` | Flower client/server + IRBA |
| `drift/` | ADWIN monitors |
| `evaluation/metrics.py` | F1, FPR, AUC, plots, ablation |
| `capture/` | Live/tshark ingest, LAN scan detection |
| `dashboard/` | Web UI + SocketIO |

---

## 5. Datasets

### 5.1 NSL-KDD (primary)

| Property | Value |
|----------|-------|
| **Source** | [UNB CIC NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) |
| **Files** | `datasets/nsl_kdd/KDDTrain+.txt`, `KDDTest+.txt` |
| **Features** | 41 (after encoding categoricals) |
| **Classes** | 5 — Normal, DoS, Probe, R2L, U2R |
| **Train size** | 125,973 flows |
| **Test size** | 22,544 flows |
| **Attack mapping** | `nmap`, `portsweep`, `satan` → Probe (2); `neptune`, `smurf` → DoS (1); etc. |

### 5.2 CICIDS2018

| Property | Value |
|----------|-------|
| **Source** | [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) |
| **Path** | `datasets/cicids2018/*.csv` |
| **Classes** | Benign, DoS/DDoS, PortScan, BruteForce, Infiltration |
| **Note** | PCAPs can be converted via `data/pcap_to_flow.py` |

### 5.3 Bot-IoT

| Property | Value |
|----------|-------|
| **Source** | [UNSW Bot-IoT](https://research.unsw.edu.au/projects/bot-iot-dataset) |
| **Path** | `datasets/bot_iot/*.csv` |
| **Classes** | Normal, DDoS, DoS, Reconnaissance, Theft |

---

## 6. Data Preprocessing Pipeline

**File:** `data/preprocess.py`

| Step | Method | Details |
|------|--------|---------|
| 1. Load | CSV / NSL-KDD fixed columns | Label encoding for `protocol_type`, `service`, `flag` |
| 2. Label map | Attack name → class ID | See `NSL_KDD_LABEL_MAP` in `config.py` |
| 3. Scale | `StandardScaler` | Fitted on train, applied to test; saved as `saved_models/scaler.pkl` |
| 4. Balance | **SMOTE** | Oversample minority classes to match majority count |
| 5. Partition | **Dirichlet Non-IID** | α=0.5 across 9 FL nodes (heterogeneous class distribution) |
| 6. Sequences | Sliding window | `SEQUENCE_LEN=10` → shape `(N, 10, 41)` for BiLSTM |

**Example (from training log):** After SMOTE, each class has ~67,343 samples; nodes receive uneven class mixes (realistic IoT federation).

---

## 7. Machine Learning Model

### 7.1 Architecture: FedAIDA-IDS

**File:** `model/fedaida_model.py` — `build_fedaida_model()`

```
Input (batch, 10, 41)
    │
    ▼
Conv1D(64, k=3) → BatchNorm → Dropout(0.3)
    │
    ▼
Conv1D(128, k=3) → BatchNorm
    │
    ▼
Bidirectional LSTM(128) → return_sequences=True
    │
    ▼
Bahdanau Attention → context vector
    │
    ▼
Dense(41, tanh) → projection
    │
    ▼
ANFIS Layer (20 rules, 5 classes) → logits
    │
    ▼
Softmax (at inference) → class probabilities
```

### 7.2 Hyperparameters (`config.py`)

| Parameter | Value |
|-----------|-------|
| `NUM_FEATURES` | 41 |
| `SEQUENCE_LEN` | 10 |
| `NUM_CLASSES` | 5 |
| `CNN_FILTERS` | 64 |
| `CNN_KERNEL` | 3 |
| `LSTM_UNITS` | 128 |
| `ATTENTION_UNITS` | 64 |
| `ANFIS_RULES` | 20 |
| `DROPOUT_RATE` | 0.3 |
| `L2_REG` | 1e-4 |
| `LEARNING_RATE` | 0.001 |
| `BATCH_SIZE` | 64 |
| `LOCAL_EPOCHS` | 5 (per FL round) |
| `MAX_EPOCHS` | 50 (centralized baseline) |

### 7.3 ANFIS (Adaptive Neuro-Fuzzy Inference System)

**File:** `model/anfis_layer.py`

Five layers:

1. **Fuzzification** — Gaussian membership functions (learnable centers σ)
2. **Rule firing** — T-norm over features per rule
3. **Normalization** — Normalize firing strengths
4. **Consequent** — Linear combination per rule/class
5. **Defuzzification** — Weighted sum → class logits

**Output for interpretability:** `get_top_rule_for_sample()` returns human-readable IF-THEN rules shown on the dashboard alert feed.

### 7.4 Loss and optimizer

- **Loss:** Sparse categorical cross-entropy (from logits)
- **Optimizer:** Adam
- **Metrics:** Accuracy, Top-3 accuracy

---

## 8. Federated Learning Framework

### 8.1 Setup

| Setting | Value |
|---------|-------|
| Framework | Flower (`flwr`) + in-process simulation in `train.py` |
| Nodes | 9 (`NUM_NODES`) |
| FL rounds | 50 default (`FL_ROUNDS`) |
| Clients per round | ≥6 (`MIN_FIT_CLIENTS`), 80% fraction (`FRACTION_FIT`) |
| Local epochs | 5 per round |
| Aggregation | **IRBA trust-weighted** (not plain FedAvg) |

### 8.2 Training round (per round)

1. Sample active (non-quarantined) nodes  
2. Each node: copy global weights → local fit on private data → optional Byzantine flip (`-weights`)  
3. IRBA: update trust (cosine + coverage + history)  
4. IRBA: aggregate weighted by trust × sample count  
5. Evaluate global model on held-out test sequences  
6. Save best weights if macro-F1 improves  

### 8.3 Flower server (optional deployment)

**File:** `federation/server.py` — `IRBAFedAvg` strategy for distributed Flower deployment (same IRBA logic as simulation).

---

## 9. IRBA Byzantine Defence

**File:** `federation/irba.py` — **Novelty N4**

**IDS-Aware Reputation-Based Aggregation (IRBA)** combines three trust signals:

| Signal | Weight | Meaning |
|--------|--------|---------|
| **Cosine similarity** | 0.4 | Local weight update vs median of all updates |
| **Coverage score** | 0.4 | Fraction of attack classes detected on validation slice |
| **Historical stability** | 0.2 | Low variance of past trust scores |

| Threshold | Value |
|-----------|-------|
| Initial trust | 0.50 |
| Max trust | 0.95 |
| **Quarantine** | trust < **0.20** |

**Byzantine simulation:** Nodes 0 and 1 send negated weights (`NUM_BYZANTINE_NODES=2`).

**Outputs:** `results/metrics/irba_trust_log.json` — per-round trust scores and quarantined nodes.

---

## 10. ADWIN Concept Drift Detection

**File:** `drift/adwin_detector.py` — **Novelty N3**

| Parameter | Value |
|-----------|-------|
| Algorithm | ADWIN (Adaptive Windowing) — River `river.drift.ADWIN` |
| `ADWIN_DELTA` | 0.002 |
| `DRIFT_CHECK_INTERVAL` | 50 samples |
| Trigger | Classification error stream per node |

When drift is detected on a node, `FederatedDriftCoordinator` logs a priority FL round trigger. Optional experiment: `simulate_concept_drift()` injects label noise after 70% of training.

---

## 11. Real-Time Deployment and LAN Scan Detection

### 11.1 Capture paths

| Mode | Description |
|------|-------------|
| **Wi-Fi (recommended)** | Windows `tshark` → `capture/incoming/` → `TsharkIngest` |
| **Live Scapy** | `capture/live_capture.py` (requires NIC access / sudo) |
| **PCAP upload** | `POST /api/capture/tshark/upload` |

### 11.2 LAN port-scan detection (same Wi-Fi)

**Files:** `capture/scan_detector.py`, `capture/network_utils.py`, `dashboard/app.py`

Detects **any device on the LAN** scanning another device when traffic is visible to the capture adapter.

| Detection | Trigger | Alert | Method |
|-----------|---------|-------|--------|
| **TCP port scan** | 8+ non-standard ports to one victim in 12s | PortScan (nmap suspected) | `lan_scan` |
| Scan **your laptop** | 6+ ports in 12s (lower threshold) | Same | `lan_scan` |
| **ARP sweep** | 8+ ARP "who-has" targets in 25s | ARP sweep (host discovery) | `arp` |

**Excluded ports (reduce false positives):** 53, 80, 443, 22, 8080, 8443, etc.

**Live alert mode:** `LIVE_ALERT_MODE = strict` — rules only on Wi-Fi; ML DoS/R2L alerts disabled to avoid noise.

**Config:** `LAN_SCAN_ENABLED = True` in `config.py`.

### 11.3 Feature extraction for live flows

**File:** `capture/live_capture.py`

- 5-tuple flow tracking, 41 NSL-KDD-compatible features  
- `MIN_FLOW_PACKETS = 3` for ML classification  
- Scan rules work on single SYN packets (no ML required)

---

## 12. Dashboard and APIs

**Files:** `dashboard/app.py`, `dashboard/templates/index.html`

### 12.1 UI sections

| Section | Function |
|---------|----------|
| **Live Traffic** | Wireshark-style packet table + IDS columns |
| **Live Alert Feed** | Attacks with Source, Destination, Method, Confidence |
| **Node Trust Scores** | IRBA visualization (9 nodes) |
| **Blocked IPs** | Auto-block if confidence > 95% |
| **FL Round** | Federated round display (training integration) |

### 12.2 Key API endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/status` | GET | Model loaded, tshark active, LAN scan, local IPs |
| `/api/load_model` | POST | Load weights for dataset |
| `/api/capture/tshark/start` | POST | Start PCAP ingest |
| `/api/capture/tshark/stop` | POST | Stop ingest |
| `/api/traffic` | GET | Packet rows JSON |
| `/api/alerts` | GET | Recent alerts |
| `/api/simulate_attack` | POST | Demo-only forced alert |
| `/api/export_log` | GET | Export alert history |

**Security:** `DASHBOARD_API_KEY` required for mutating routes; CORS restricted to localhost by default.

---

## 13. Training Pipeline and Commands

### 13.1 Main script

```bash
python3 train.py --dataset nsl_kdd --rounds 50
python3 train.py --dataset nsl_kdd --rounds 50 --byzantine
python3 train.py --dataset nsl_kdd --rounds 50 --byzantine --ablation --drift_test --multi_seed
python3 train.py --dataset nsl_kdd --eval_only
python3 train.py --dataset nsl_kdd --centralized
```

**Full paper pipeline:** `scripts/run_paper_training.sh` → `logs/paper_full_pipeline.log`

### 13.2 Training stages in `train.py`

1. Load & preprocess dataset  
2. Configure Byzantine nodes (optional)  
3. Federated training (`FedAIDASimulation.train`)  
4. Final evaluation → `final_metrics.json`  
5. Generate plots (FL convergence, trust, drift)  
6. Ablation / multi-seed / drift experiments (flags)

---

## 14. Evaluation Metrics and Results

### 14.1 Metrics computed

**File:** `evaluation/metrics.py` — `evaluate_model()`

| Metric | Description |
|--------|-------------|
| Accuracy | Overall correct classifications |
| Precision | Macro-averaged |
| Recall | Macro-averaged |
| **Macro F1** | Primary paper metric |
| **FPR** | False positive rate from confusion matrix |
| **AUC** | Macro one-vs-rest ROC AUC |
| Per-class report | sklearn `classification_report` |

### 14.2 Saved results on disk (current workspace)

#### `results/metrics/eval_metrics.json` (eval-only run)

| Metric | Value |
|--------|-------|
| Dataset | nsl_kdd_eval |
| Accuracy | 0.1975 |
| Precision | 0.1210 |
| Recall | 0.1991 |
| Macro F1 | 0.1414 |
| FPR | 0.1961 |
| AUC | 0.5059 |

**Note:** This reflects an `--eval_only` snapshot; scores improve after full 50-round FL training. Re-run `train.py --rounds 50` and check `final_metrics.json` for paper numbers.

#### `results/metrics/fl_round_metrics.json` (partial FL log)

Example early rounds:

| Round | F1 | Accuracy | Quarantined |
|-------|-----|----------|-------------|
| 1 | 0.1538 | 0.30 | [] |
| 2 | (in progress) | — | — |

Full 50-round training log: `logs/paper_full_pipeline.log` (Round 1 reported F1≈0.1077, Acc≈0.1284).

#### `results/plots/`

| File | Description |
|------|-------------|
| `confusion_matrix_nsl_kdd_eval.png` | Confusion matrix |
| `roc_nsl_kdd_eval.png` | ROC curves |
| `fl_convergence.png` | (after full train) FL F1 vs round |
| `trust_scores.png` | IRBA trust over rounds |
| `byzantine_experiment.png` | (from `scripts/byzantine_test.py`) |

### 14.3 Expected outputs after full training

| Artifact | Path |
|----------|------|
| Best model weights | `saved_models/best_global_model.weights.h5` |
| Final model weights | `saved_models/final_global_model.weights.h5` |
| Scaler | `saved_models/scaler.pkl` |
| Final metrics | `results/metrics/final_metrics.json` |
| FL round history | `results/metrics/fl_round_metrics.json` |
| IRBA log | `results/metrics/irba_trust_log.json` |
| Ablation | `results/metrics/ablation_results.json` (with `--ablation`) |
| Multi-seed | `results/metrics/multi_seed_results.json` (with `--multi_seed`) |

---

## 15. Outputs and Artifacts

```
fedaida_ids/
├── saved_models/              # Trained weights (.h5), scaler.pkl
├── results/
│   ├── metrics/               # JSON metrics for paper tables
│   └── plots/                 # PNG figures for paper
├── logs/
│   ├── fedaida_train.log
│   ├── paper_full_pipeline.log
│   └── byzantine_test.log
├── capture/
│   ├── incoming/              # Live PCAP from Windows tshark
│   └── processed/               # Archived PCAP chunks
└── docs/
    ├── PROJECT_REPORT.md        # This document
    ├── wireshark_wifi_capture.md
    ├── realtime_demo_runbook.md
    ├── PAPER_TRAINING.md
    └── datasets_download.md
```

---

## 16. Technology Stack

| Layer | Technology | Version (requirements.txt) |
|-------|------------|---------------------------|
| Deep learning | TensorFlow/Keras | 2.15.0 |
| Federated learning | Flower (flwr) | 1.6.0 |
| Drift detection | River (ADWIN) | 0.21.0 |
| Fuzzy logic | scikit-fuzzy | 0.4.2 |
| Data | pandas, numpy, scikit-learn | 2.1.4 / 1.26.2 / 1.3.2 |
| Imbalance | imbalanced-learn (SMOTE) | 0.11.0 |
| Explainability | SHAP | 0.44.0 |
| Dashboard | Flask, Flask-SocketIO, Flask-CORS | 3.0.0 / 5.3.6 |
| Capture | Scapy | 2.5.0 |
| Visualization | matplotlib, seaborn, plotly | 3.8.2 / 0.13.0 |
| Testing | pytest | 8.3.3 |
| Experiment tracking | wandb (optional) | 0.16.1 |

---

## 17. Testing and CI

| Test file | Coverage |
|-----------|----------|
| `tests/test_model.py` | Model build, forward pass |
| `tests/test_preprocess.py` | Preprocessing helpers |
| `tests/test_scan_detector.py` | LAN scan + ARP sweep |
| `tests/test_wireshark_view.py` | Packet row formatting |
| `tests/test_training_smoke.py` | Short training smoke test |

**CI:** `.github/workflows/ci.yml` — Python 3.10, `pip install -r requirements.txt`, `pytest`

**Diagnostics:**

```bash
./scripts/check_tshark_setup.sh
.venv/bin/python scripts/verify_lan_scan_detection.py
```

---

## 18. Limitations and Future Work

| Limitation | Detail |
|------------|--------|
| Wi-Fi visibility | May not see all client-to-client traffic (AP client isolation) |
| Live ML features | 41-dim proxy features from PCAP ≠ exact NSL-KDD training features |
| Class imbalance | U2R rare even after SMOTE |
| Full FL runtime | 50 rounds on CPU can take hours |
| Distributed Flower | Production FL uses in-process sim; `server.py` for scale-out |
| UDP scans | LAN rules focus on TCP SYN |

**Future work:** Full CICIDS/Bot-IoT training runs, GPU acceleration, tighter live-feature alignment, AP mirror port for full-LAN visibility.

---

## 19. How to Run (Quick Reference)

### Training

```bash
cd fedaida_ids
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 train.py --dataset nsl_kdd --rounds 50 --byzantine
```

### Dashboard + Wi-Fi + LAN scan detection

```powershell
# Windows Admin
.\scripts\start_wifi_tshark_windows.ps1 -Interface 5
```

```bash
# WSL
export DASHBOARD_API_KEY=demo-key
./scripts/run_dashboard.sh
# Browser: Load Model → Start WiFi Capture (tshark)
```

### Verify LAN scan logic

```bash
.venv/bin/python scripts/verify_lan_scan_detection.py
```

### Viva demo (teammate scans your laptop)

```bash
nmap -sS <your-wifi-ip>
```

Expect: **PortScan (nmap suspected)**, Method **lan_scan**, scanner IP in Source column.

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | May 2026 | Initial architecture and training pipeline |
| 1.1 | Jun 2026 | Wi-Fi tshark ingest, Wireshark UI, LAN scan detection, strict live alerts |
| 1.2 | Jun 2026 | Full project report (this document) |

---

*End of report*
