#!/usr/bin/env bash
# Start dashboard with project venv (required for Scapy/tshark ingest)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -d ".venv" ]; then
  echo "Creating .venv — run once: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi

export DASHBOARD_API_KEY="${DASHBOARD_API_KEY:-demo-key}"
echo "API key: $DASHBOARD_API_KEY"
echo "Open http://127.0.0.1:5000"
echo "For Wi-Fi: run start_wifi_tshark_windows.ps1 on Windows FIRST, then Start WiFi Capture (tshark)."
exec .venv/bin/python dashboard/app.py
