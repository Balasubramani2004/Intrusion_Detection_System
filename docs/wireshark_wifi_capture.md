# Wireshark / tshark Wi-Fi Capture for FedAIDA-IDS

Use this workflow to detect intrusions from **your real connected Wi-Fi traffic** when running the project in WSL.

WSL cannot sniff the host Wi-Fi adapter directly. Capture on **Windows** with tshark (same engine as Wireshark), then ingest PCAP chunks in WSL.

## Architecture

1. **Windows:** `tshark` captures Wi-Fi → writes rolling files to `capture/incoming/`
2. **WSL:** dashboard watches that folder → extracts flows → classifies → alerts

## Prerequisites

- Wireshark/tshark installed on **Windows** ([download](https://www.wireshark.org/download.html))
- FedAIDA dashboard running in WSL
- API key set: `export DASHBOARD_API_KEY=demo-key`

## Step 1 — List Wi-Fi interface (Windows PowerShell)

```powershell
tshark -D
```

Note the interface number for Wi-Fi (e.g. `5`).

## Step 2 — Start Windows capture

From the project folder in PowerShell (Run as Administrator if capture fails):

```powershell
cd \\wsl$\Ubuntu\home\balu\projects\IDS\fedaida_ids
.\scripts\start_wifi_tshark_windows.ps1
```

Or specify interface:

```powershell
.\scripts\start_wifi_tshark_windows.ps1 -Interface 5
```

Files appear under WSL path:

`fedaida_ids/capture/incoming/wifi_00001.pcapng`, etc.

## Step 3 — Start WSL ingest + dashboard

```bash
cd ~/projects/IDS/fedaida_ids
source .venv/bin/activate
export DASHBOARD_API_KEY=demo-key
python dashboard/app.py
```

Open `http://localhost:5000`, enter API key, click **Load Model**, then **Start WiFi Capture (tshark)**.

## Compare with Wireshark (side-by-side)

The dashboard **Live Traffic — Wireshark View + IDS** table uses the same columns as Wireshark’s packet list:

| Wireshark | Dashboard |
|-----------|-----------|
| No. | No. |
| Time | Time (`YYYY-MM-DD HH:MM:SS.microseconds`) |
| Source | Source (MAC or IP) |
| Destination | Destination (MAC, IP, or Broadcast) |
| Protocol | Protocol (ARP, ICMPv6, UDP, TCP, …) |
| Length | Length (bytes) |
| Info | Info (e.g. ARP “Who has …”, UDP `51449 → 443 Len=…`) |

Extra IDS columns (after a flow is classified): **Detection**, **Confidence**, **Severity**.

**Validation:** capture the same moment in Wireshark and in the dashboard. ARP rows should match line-for-line on Info; UDP/TCP rows should show the same ports and lengths. IP flows also get Normal/attack labels once enough packets form a flow (`MIN_FLOW_PACKETS`, default 3).

REST: `GET /api/traffic?limit=200` returns the same rows as JSON.

## Step 4 — Generate traffic

Browse the web, stream video, or run a controlled scan from another device on the same LAN. Alerts should show **real source IPs** from captured packets.

## Alternative: upload a Wireshark PCAP

1. In Wireshark: Capture on Wi-Fi → Stop → **File → Save As** `.pcapng`
2. Copy file into WSL `capture/incoming/` or use API:

```bash
curl -X POST http://127.0.0.1:5000/api/capture/tshark/upload \
  -H "X-API-Key: demo-key" \
  -F "file=@/path/to/your_capture.pcapng"
```

## CLI ingest (optional)

Watch folder without dashboard:

```bash
python -m capture.tshark_ingest --watch --incoming capture/incoming
```

Process one file:

```bash
python -m capture.tshark_ingest --file capture/incoming/wifi_00001.pcapng
```

## Alert policy

Real Wi-Fi/tshark flows only raise alerts when:

- predicted class is not Normal, **and**
- confidence ≥ `0.70` (`ALERT_CONFIDENCE_THRESHOLD` in `config.py`)

Demo buttons (`Simulate PortScan`, etc.) still force high-confidence alerts for presentations.

## Validation checklist

- [ ] `tshark -D` shows Wi-Fi interface on Windows
- [ ] Rolling PCAP files appear in `capture/incoming/`
- [ ] Dashboard shows **tshark active**
- [ ] `Flows Analysed` increases after traffic
- [ ] Alert feed shows plausible source IPs (not random 192.168.x.x demo IPs)
- [ ] **Live Traffic** table shows ARP/UDP rows matching Wireshark Info column
- [ ] `GET /api/traffic` returns packet rows with matching No/Time/Protocol/Length
- [ ] `GET /api/export_log` contains alert history

## Troubleshooting

### Empty Live Traffic table (no Protocol / Destination / Length)

| Symptom | Cause | Fix |
|---------|--------|-----|
| Table says "No packets yet" | **Start Monitoring** only — synthetic demo, no packets | Stop monitoring; use **Start WiFi Capture (tshark)** |
| Banner: "Capture started but no packets" | tshark ingest on, Windows script not writing | Run `scripts/start_wifi_tshark_windows.ps1` as Admin on Windows |
| `GET /api/traffic` returns `"packets": []` | Nothing ingested yet | Check `capture/incoming/` for `.pcapng` files; wait ~2s after each chunk |
| Only random `192.168.x.x` in alerts | Demo mode | Not real Wi-Fi — follow Wi-Fi steps above |
| Using `eth0` in WSL | WSL interface is not host Wi-Fi | Use Windows tshark → WSL folder ingest (not live capture on eth0) |

**Quick test without Wi-Fi:** Save a `.pcapng` from Wireshark and upload:

```bash
curl -X POST http://127.0.0.1:5000/api/capture/tshark/upload \
  -H "X-API-Key: demo-key" \
  -F "file=@/path/to/capture.pcapng"
```

The **Live Traffic** table (top of dashboard, under stats) should fill immediately with Protocol, Destination, and Length.

### Other issues

| Issue | Fix |
|--------|-----|
| Permission denied on Windows capture | Run PowerShell as Administrator |
| No files in `incoming/` | Check `\\wsl$\Ubuntu\...` path matches your WSL distro name |
| tshark ingest inactive immediately | Ensure Windows script is running and writing files |
| Banner shows stale message after 30s | Restart Windows tshark script; confirm files appear in `incoming/` |
| No alerts on real traffic | Load model first; generate more traffic; lower threshold via `DASHBOARD_ALERT_CONFIDENCE=0.6` |
| Thousands of fake alerts | Do not use **Start Monitoring** for Wi-Fi testing; it no longer raises alerts (use Simulate buttons or tshark) |
