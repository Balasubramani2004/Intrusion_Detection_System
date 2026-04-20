# FedAIDA-IDS
## Federated Self-Learning Neuro-Fuzzy Intrusion Detection System for IoT Networks

**Team:** Balasubramani M | Guna B V | Sinchana B G  
**Guide:** Dr. Pankaja  
**Institution:** Cambridge Institute of Technology, Bengaluru  
**Target Journal:** Future Generation Computer Systems (Elsevier, IF 7.5)

---

## Novelty Claims
| # | Claim | Implementation |
|---|---|---|
| N1 | CNN+BiLSTM+Attention as FL local learner | `model/fedaida_model.py` |
| N2 | ANFIS interpretable fuzzy rules | `model/fedaida_model.py → ANFISLayer` |
| N3 | ADWIN self-learning drift detection | `drift/adwin_detector.py` |
| N4 | IRBA Byzantine poisoning defence | `federation/irba.py` |
| N5 | Modern IoT dataset evaluation | NSL-KDD + CICIDS + Bot-IoT |

---

## Project Structure
```
fedaida_ids/
├── config.py                  ← All hyperparameters (edit this first)
├── train.py                   ← Main training entry point
├── requirements.txt
│
├── data/
│   └── preprocess.py          ← Load, clean, SMOTE, Non-IID partition
│
├── model/
│   └── fedaida_model.py       ← CNN + BiLSTM + Attention + ANFIS
│
├── federation/
│   ├── client.py              ← Flower FL client per node
│   ├── server.py              ← Flower FL server with IRBA
│   └── irba.py                ← IRBA trust scoring (Novelty N4)
│
├── drift/
│   └── adwin_detector.py      ← ADWIN concept drift (Novelty N3)
│
├── evaluation/
│   └── metrics.py             ← F1, FPR, confusion matrix, ROC, plots
│
├── dashboard/
│   ├── app.py                 ← Flask + SocketIO real-time dashboard
│   └── templates/index.html   ← Dashboard UI
│
├── capture/
│   └── live_capture.py        ← Live packet capture (Scapy)
│
├── scripts/
│   └── byzantine_test.py      ← Byzantine attack experiment
│
└── datasets/                  ← PUT YOUR DATASETS HERE
    ├── nsl_kdd/
    │   ├── KDDTrain+.txt       ← Download from UNB
    │   └── KDDTest+.txt
    ├── cicids2017/
    │   └── *.csv               ← Download from CIC
    └── bot_iot/
        └── *.csv               ← Download from UNSW
```

---

## ✅ TODO LIST — Do This After Downloading

### Step 1 — Install Dependencies
```bash
# In WSL / Ubuntu terminal
cd fedaida_ids
python3 -m venv fedaida_env
source fedaida_env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2 — Download Datasets (FREE)

**NSL-KDD** (500 MB) — REQUIRED FIRST
- Go to: https://www.unb.ca/cic/datasets/nsl.html
- Download: `KDDTrain+.txt` and `KDDTest+.txt`
- Put both in: `datasets/nsl_kdd/`

**CICIDS2017** (8 GB) — PHASE 2
- Go to: https://www.unb.ca/cic/datasets/ids-2017.html
- Download: all CSV files (NOT the PCAPs — too large)
- Put all CSVs in: `datasets/cicids2017/`

**Bot-IoT** (1.2 GB) — PHASE 2
- Go to: https://research.unsw.edu.au/projects/bot-iot-dataset
- Download: CSV files (feature-extracted version)
- Put CSVs in: `datasets/bot_iot/`

### Step 3 — Verify Setup
```bash
python3 -c "
import tensorflow as tf, flwr as fl, river, skfuzzy, flask
print('TF:', tf.__version__)
print('Flower:', fl.__version__)
print('All OK — ready to train')
"
```

### Step 4 — Train (NSL-KDD first)
```bash
# Basic training — NSL-KDD, 50 rounds, 9 nodes
python3 train.py --dataset nsl_kdd --rounds 50

# With Byzantine attack simulation (for paper experiment)
python3 train.py --dataset nsl_kdd --rounds 50 --byzantine

# Full: ablation + drift test + multi-seed evaluation
python3 train.py --dataset nsl_kdd --rounds 50 --byzantine --ablation --drift_test --multi_seed
```

### Step 5 — Run on College GPU
```bash
# Check GPU
nvidia-smi
# Train with GPU (TF uses GPU automatically)
python3 train.py --dataset cicids --rounds 50 --byzantine --ablation
```

### Step 6 — View Results
```bash
# Results saved to:
# results/plots/   — confusion matrix, ROC curves, FL convergence, trust scores
# results/metrics/ — JSON files with all numbers for the paper
# saved_models/    — trained weights (.h5 files)

ls results/plots/      # all paper figures
cat results/metrics/final_metrics.json   # F1, FPR, precision, recall
```

### Step 7 — Byzantine Experiment (Novelty N4)
```bash
python3 scripts/byzantine_test.py --dataset nsl_kdd --rounds 30 --byzantine 2
# Output: results/plots/byzantine_experiment.png
# This is your paper Figure 2
```

### Step 8 — Run Dashboard
```bash
# After training is complete:
python3 dashboard/app.py
# Open browser: http://localhost:5000
# Click "Start Monitoring" for live demo
```

### Step 9 — Live Demo on College Network (Viva Day)
```bash
# On Machine 1 (runs FedAIDA-IDS):
sudo python3 capture/live_capture.py --interface eth0

# On Machine 2 (simulates attack):
nmap -sS 192.168.x.x   # port scan — FedAIDA detects within 3 seconds
```

---

## Training Commands Reference

| Command | Purpose |
|---|---|
| `python3 train.py --dataset nsl_kdd` | Basic training |
| `python3 train.py --byzantine` | Byzantine attack test |
| `python3 train.py --ablation` | Ablation study |
| `python3 train.py --drift_test` | Drift detection experiment |
| `python3 train.py --multi_seed` | 5-seed statistical validation |
| `python3 train.py --eval_only` | Evaluate saved model |
| `python3 scripts/byzantine_test.py` | Full Byzantine comparison |
| `python3 dashboard/app.py` | Start dashboard |

---

## Expected Results (Paper Targets)

| Metric | Target |
|---|---|
| Macro F1 (Bot-IoT) | > 0.94 |
| False Positive Rate | < 1.0% |
| IRBA vs FedAvg (Byzantine) | F1 0.91 vs 0.62 |
| Drift Recovery | ≤ 4 FL rounds |
| Training time vs centralised | ~45% faster |

---

## Config Adjustments for College GPU

Edit `config.py`:
```python
BATCH_SIZE   = 128    # increase for GPU (default 64)
MAX_EPOCHS   = 100    # more epochs possible on GPU
FL_ROUNDS    = 100    # more rounds for better convergence
NUM_NODES    = 9      # keep as is
```

---

## Paper Figures Generated Automatically

After training, `results/plots/` contains:
- `final_confusion_matrix.png` → Table 1
- `final_roc_curves.png`       → Figure 1
- `fl_convergence.png`         → Figure 2
- `trust_scores.png`           → Figure 3
- `byzantine_experiment.png`   → Figure 4
- `drift_recovery.png`         → Figure 5

All figures are publication-quality at 150 DPI.

---

## Team Responsibilities

| Member | Owns | Files |
|---|---|---|
| Student 1 | Model + Training | `model/`, `train.py` |
| Student 2 | Data + Federation | `data/`, `federation/`, `scripts/` |
| Student 3 | Dashboard + Paper | `dashboard/`, Overleaf |

---

## Citation of Base Paper
Tsang, Y.P. and Wu, C.H., 2023. A Federated-ANFIS for Collaborative 
Intrusion Detection in Securing Decentralized Autonomous Organizations.
*IEEE Transactions on Engineering Management.*

FedAIDA-IDS extends FANFIS with: temporal BiLSTM local learner (N1),
interpretable ANFIS rules (N2), ADWIN drift adaptation (N3),
IRBA Byzantine defence (N4), and modern IoT dataset evaluation (N5).
