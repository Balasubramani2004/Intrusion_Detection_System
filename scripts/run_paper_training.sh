#!/usr/bin/env bash
# Run paper-scale FedAIDA-IDS experiments (long-running).
# Usage: bash scripts/run_paper_training.sh [quick]
#   quick — 5 FL rounds for CI/dev smoke (default: 50 rounds)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source .venv/bin/activate
mkdir -p logs results/metrics results/plots saved_models

ROUNDS="${PAPER_ROUNDS:-50}"
if [[ "${1:-}" == "quick" ]]; then ROUNDS=5; fi

LOG="logs/paper_training_$(date +%Y%m%d_%H%M%S).log"
echo "Logging to $LOG (rounds=$ROUNDS)"

echo "=== NSL-KDD FL + Byzantine ($ROUNDS rounds) ===" | tee -a "$LOG"
python train.py --dataset nsl_kdd --rounds "$ROUNDS" --byzantine 2>&1 | tee -a "$LOG"

echo "=== NSL-KDD optional: ablation + drift + multi_seed ===" | tee -a "$LOG"
python train.py --dataset nsl_kdd --rounds "$ROUNDS" --byzantine \
  --ablation --drift_test --multi_seed 2>&1 | tee -a "$LOG"

echo "=== Bot-IoT (sample CSVs) ===" | tee -a "$LOG"
python train.py --dataset bot_iot --rounds "$ROUNDS" --byzantine \
  --ablation --drift_test --multi_seed 2>&1 | tee -a "$LOG" || true

echo "=== Byzantine comparison figure ===" | tee -a "$LOG"
python scripts/byzantine_test.py --dataset nsl_kdd --rounds 30 --byzantine 2 2>&1 | tee -a "$LOG"

echo "=== Artifacts ===" | tee -a "$LOG"
ls -la results/metrics/ results/plots/ saved_models/ | tee -a "$LOG"
echo "Done. See $LOG"
