#!/usr/bin/env bash
# Quick diagnostics for Windows tshark → WSL ingest pipeline
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INCOMING="$ROOT/capture/incoming"
PROCESSED="$ROOT/capture/processed"
TSHARK_WIN="/mnt/c/Program Files/Wireshark/tshark.exe"

echo "=== FedAIDA tshark setup check ==="
echo "Project: $ROOT"
echo ""

echo "--- WSL incoming/ ---"
ls -la "$INCOMING" 2>/dev/null || echo "(missing)"
PCAP_COUNT=$(find "$INCOMING" -maxdepth 1 \( -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null | wc -l)
echo "PCAP files in incoming: $PCAP_COUNT"
if [ "$PCAP_COUNT" -eq 0 ]; then
  echo "  >> No capture files. On Windows (Admin PowerShell):"
  echo "     cd $ROOT  (from Windows: \\\\wsl\$\\Ubuntu\\home\\balu\\projects\\IDS\\fedaida_ids)"
  echo "     .\\scripts\\start_wifi_tshark_windows.ps1"
fi
echo ""

echo "--- WSL processed/ (recent) ---"
ls -lt "$PROCESSED"/*.pcapng 2>/dev/null | head -3 || echo "(no processed pcaps)"
echo ""

echo "--- Windows tshark ---"
if [ -x "$TSHARK_WIN" ]; then
  echo "Found: $TSHARK_WIN"
  "$TSHARK_WIN" -D 2>&1 | head -12
else
  echo "NOT FOUND at $TSHARK_WIN — install Wireshark on Windows."
fi
echo ""

echo "--- Python / Scapy (WSL ingest) ---"
PY="$ROOT/.venv/bin/python"
if [ -x "$PY" ] && "$PY" -c "import scapy" 2>/dev/null; then
  echo "Scapy: OK ($PY)"
elif python3 -c "import scapy" 2>/dev/null; then
  echo "Scapy: OK (system python3)"
else
  echo "Scapy: MISSING — use: ./scripts/run_dashboard.sh  (or: .venv/bin/pip install -r requirements.txt)"
fi
echo ""

echo "--- Test ingest one processed file (optional) ---"
LATEST=$(ls -t "$PROCESSED"/*.pcapng 2>/dev/null | head -1 || true)
PY="${PY:-python3}"
[ -x "$ROOT/.venv/bin/python" ] && PY="$ROOT/.venv/bin/python"
if [ -n "$LATEST" ] && "$PY" -c "import scapy" 2>/dev/null; then
  "$PY" -c "
from scapy.all import rdpcap
p='$LATEST'
n=len(rdpcap(p))
print(f'Read {n} packets from {p.split(\"/\")[-1]}')
"
else
  echo "Skip (no sample pcap or no scapy)"
fi
echo ""
echo ""
echo "--- LAN scan detection logic ---"
if [ -x "$ROOT/.venv/bin/python" ]; then
  "$ROOT/.venv/bin/python" "$ROOT/scripts/verify_lan_scan_detection.py" 2>&1 || true
else
  echo "Skip (no .venv)"
fi
echo ""
echo "Done. Dashboard: Load Model → Start WiFi Capture (tshark) while Windows script runs."
echo "Banner should show: LAN scan watch: ON"
