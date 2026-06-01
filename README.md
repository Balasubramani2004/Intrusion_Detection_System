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
    ├── cicids2018/
    │   └── *.csv               ← Download from CIC (CSE-CIC-IDS2018)
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

**CSE-CIC-IDS2018** (large) — PHASE 2
- Go to: https://www.unb.ca/cic/datasets/ids-2018.html
- Put CSV files in: `datasets/cicids2018/`
- If you only have PCAP/PCAPNG: place them in `datasets/cicids2018/` and the code can extract flow CSVs into `datasets/cicids2018/extracted_csv/`

**Bot-IoT** (1.2 GB) — PHASE 2
- Go to: https://research.unsw.edu.au/projects/bot-iot-dataset
- Download: CSV files (feature-extracted version)
- Put CSVs in: `datasets/bot_iot/`
- Full instructions: `docs/datasets_download.md`
- Verify: `bash scripts/verify_datasets.sh`

### Step 3 — Verify Setup
```bash
python3 -c "
import tensorflow as tf, flwr as fl, river, skfuzzy, flask
print('TF:', tf.__version__)
print('Flower:', fl.__version__)
print('All OK — ready to train')
"
```

### Step 3.1 — Install Test Tooling and Run Smoke Tests
```bash
pip install -r requirements.txt
python3 -m pytest
```

### Step 4 — Train (NSL-KDD first)
```bash
# Basic training — NSL-KDD, 50 rounds, 9 nodes
python3 train.py --dataset nsl_kdd --rounds 50

# With Byzantine attack simulation (for paper experiment)
python3 train.py --dataset nsl_kdd --rounds 50 --byzantine

# Full: ablation + drift test + multi-seed evaluation
python3 train.py --dataset nsl_kdd --rounds 50 --byzantine --ablation --drift_test --multi_seed

# Long runs: see docs/PAPER_TRAINING.md and scripts/run_paper_training.sh
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

### Step 8 — Run Dashboard (real Wi-Fi demo)

```bash
# After training is complete:
export DASHBOARD_API_KEY="demo-key"
export DASHBOARD_CORS_ORIGINS="http://localhost:5000,http://127.0.0.1:5000"
python3 dashboard/app.py
# Open browser: http://localhost:5000
```

**Real Wi-Fi traffic (recommended for viva):**

1. **Windows (PowerShell Admin):** run `scripts/start_wifi_tshark_windows.ps1`
2. **WSL:** start dashboard (above), enter API key, click **Load Model**
3. Click **Start WiFi Capture (tshark)** — not "Start Monitoring" (synthetic demo only)
4. Compare **Live Traffic** table with Wireshark (Protocol, Destination, Length, Info)

See `docs/wireshark_wifi_capture.md` for full workflow and troubleshooting.

**Synthetic demo only:** click **Simulate PortScan / DDoS / Recon** after Load Model.

### Step 9 — Live Demo on College Network (Viva Day)

**Option A — Wi-Fi via Windows tshark (WSL + laptop Wi-Fi):**

```powershell
# Windows host
cd \\wsl$\Ubuntu\home\<user>\projects\IDS\fedaida_ids
.\scripts\start_wifi_tshark_windows.ps1
```

```bash
# WSL — dashboard + ingest
export DASHBOARD_API_KEY=demo-key
python3 dashboard/app.py
# UI: Load Model → Start WiFi Capture (tshark)
```

**Option B — Native Linux capture (machine with NIC access):**

```bash
sudo python3 capture/live_capture.py --interface eth0
# Dashboard: Start Live Capture (same API key workflow)
```

**Attack simulation (second machine on LAN):**

```bash
nmap -sS 192.168.x.x   # port scan — check Live Alert Feed + Detection column
```

Rehearsal checklist: `docs/realtime_demo_runbook.md`

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

## Dashboard Security Notes

- Mutating dashboard endpoints require `X-API-Key` (or `Authorization: Bearer <key>`).
- Set `DASHBOARD_API_KEY` before launching `dashboard/app.py`.
- Default CORS is restricted to localhost origins; adjust using `DASHBOARD_CORS_ORIGINS`.
- Protected API routes include:
  - `POST /api/load_model`
  - `POST /api/simulate_attack`
  - `POST /api/update_fl_round`
  - `POST /api/unblock/<ip>`
  - `POST /api/unblock_all`

---

## Development and Validation Checklist

Run this checklist before merging changes:

```bash
# 1) Install project dependencies
pip install -r requirements.txt

# 2) Execute automated tests
python3 -m pytest

# 3) Run one short training smoke path
python3 train.py --dataset nsl_kdd --rounds 1 --nodes 3

# 4) Start dashboard with API key enabled
export DASHBOARD_API_KEY="local-dev-key"
python3 dashboard/app.py
```

Expected outcomes:
- Tests pass without errors.
- `train.py` produces metrics/model artifacts under `results/` and `saved_models/`.
- Dashboard starts and read-only endpoints work without auth.
- Mutating dashboard endpoints reject requests without API key.

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
