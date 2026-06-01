#!/usr/bin/env bash
# Verify FedAIDA-IDS dataset layout (does not download — see docs/datasets_download.md)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== NSL-KDD ==="
for f in KDDTrain+.txt KDDTest+.txt; do
  p="datasets/nsl_kdd/$f"
  if [[ -f "$p" ]]; then echo "  OK $p ($(wc -l < "$p") lines)"; else echo "  MISSING $p"; fi
done

echo "=== Bot-IoT ==="
n=$(find datasets/bot_iot -maxdepth 1 -name '*.csv' 2>/dev/null | wc -l)
echo "  CSV files: $n"
if [[ "$n" -ge 4 ]]; then echo "  OK (sample or full set present)"; else echo "  WARN: need more CSVs — see docs/datasets_download.md"; fi

echo "=== CICIDS2018 ==="
n=$(find datasets/cicids2018 -maxdepth 2 -name '*.csv' 2>/dev/null | wc -l)
echo "  CSV files: $n"
if [[ "$n" -ge 1 ]]; then echo "  OK (partial or full)"; else echo "  WARN: no CSVs — see docs/datasets_download.md"; fi

echo "=== Done ==="
