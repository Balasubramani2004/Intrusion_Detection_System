#!/usr/bin/env bash
# Copy latest processed PCAP into incoming/ to test WSL ingest without Windows tshark
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/capture/processed"
DST="$ROOT/capture/incoming"
LATEST=$(ls -t "$SRC"/*.pcapng 2>/dev/null | head -1 || true)
if [ -z "$LATEST" ]; then
  echo "No .pcapng in $SRC"
  exit 1
fi
mkdir -p "$DST"
NAME="replay_$(basename "$LATEST")"
cp -f "$LATEST" "$DST/$NAME"
echo "Copied to $DST/$NAME"
echo "Start WiFi Capture (tshark) on the dashboard to ingest."
