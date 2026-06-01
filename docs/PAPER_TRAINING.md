# Paper-Scale Training

Full federated training on NSL-KDD (~9 nodes, 5 local epochs/round) takes **~8–15 minutes per FL round** on CPU. Plan for **several hours** for 50 rounds.

## Quick artifacts (5 rounds, ~45–90 min)

```bash
cd fedaida_ids
source .venv/bin/activate
python train.py --dataset nsl_kdd --rounds 5 --byzantine --nodes 6
```

Produces: `results/metrics/final_metrics.json`, `results/plots/fl_convergence.png`, updated `saved_models/best_global_model.weights.h5`

## Full paper run (50 rounds, overnight)

```bash
bash scripts/run_paper_training.sh
# or background:
nohup bash scripts/run_paper_training.sh >> logs/paper_training.log 2>&1 &
tail -f logs/paper_training.log
```

Environment override:

```bash
PAPER_ROUNDS=50 bash scripts/run_paper_training.sh
PAPER_ROUNDS=5 bash scripts/run_paper_training.sh quick
```

## Full pipeline (byzantine + ablation + drift + multi_seed)

```bash
python train.py --dataset nsl_kdd --rounds 50 --byzantine \
  --ablation --drift_test --multi_seed
```

## Byzantine figure only

```bash
python scripts/byzantine_test.py --dataset nsl_kdd --rounds 30 --byzantine 2
# Output: results/plots/byzantine_experiment.png
```

## Evaluate saved weights only

```bash
python train.py --dataset nsl_kdd --eval_only
# Output: results/metrics/eval_metrics.json, results/plots/confusion_matrix_nsl_kdd_eval.png
```

## Expected outputs

| Path | Description |
|------|-------------|
| `results/metrics/final_metrics.json` | Test-set macro F1, FPR, AUC |
| `results/metrics/ablation_results.json` | With `--ablation` |
| `results/metrics/drift_recovery_metrics.json` | With `--drift_test` |
| `results/metrics/multi_seed_results.json` | With `--multi_seed` |
| `results/plots/*.png` | Confusion matrix, ROC, FL convergence, trust, byzantine, drift |

## Bot-IoT / CICIDS2018

Requires full CSV downloads — see [`datasets_download.md`](datasets_download.md). Sample Bot-IoT files support smoke runs only.
