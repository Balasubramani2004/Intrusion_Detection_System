# Wireshark / tshark Wi-Fi Capture for FedAIDA-IDS

Use this workflow to detect intrusions from **your real connected Wi-Fi traffic** when running the project in WSL.

WSL cannot sniff the host Wi-Fi adapter directly. Capture on **Windows** with tshark (same engine as Wireshark), then ingest PCAP chunks in WSL.

## Architecture

1. **Windows:** `tshark` captures Wi-Fi → writes rolling files to `capture/incoming/`
2. **WSL:** dashboard watches that folder → extracts flows → classifies → alerts

## LAN scan detection (anyone on same Wi-Fi)

**Yes — you can detect port scans** from devices on the same Wi-Fi when that traffic is visible to your capture.

| What | Threshold (see `config.py`) |
|------|-----------------------------|
| **TCP port scan** (`nmap -sS`) | **8+ non-standard ports** on one victim in **12s** (Method: `lan_scan`) |
| Scan **your laptop** | **6+ ports** in 12s (lower threshold) |
| **ARP sweep** (`nmap -sn`) | **8+ hosts** in 25s (Method: `arp`) |

- Alert **Source** = scanner IP | **Destination** = victim IP
- Ports 80, 443, 53, 22, … are ignored (normal web traffic)
- Banner: `LAN scan watch: ON (this PC: 192.168.x.x)`

**Limits:** Consumer Wi-Fi may use **client isolation** — you always see scans **to your PC**; scans between two other phones may be hidden unless the AP allows it. Promiscuous mode is **ON** by default in `start_wifi_tshark_windows.ps1`.

Verify detection logic (no live nmap needed):

```bash
.venv/bin/python scripts/verify_lan_scan_detection.py
```

## Option A — College Wi-Fi demo (recommended)

1. Windows (Admin): `.\scripts\start_wifi_tshark_windows.ps1 -Interface 5`
2. WSL: `./scripts/run_dashboard.sh` → **Load Model** → **Start WiFi Capture (tshark)**
3. Teammate (lab permission): `nmap -sS <your-wifi-ip>`
4. Expect **PortScan (nmap suspected)**, Method **lan_scan**, scanner IP in Source column

**Demo script for teammate (authorized lab only):**

```bash
# On scanner laptop — replace with your laptop's Wi-Fi IP from ipconfig / ifconfig
nmap -sS 192.168.x.x
```

**Your side:** Load Model → **Start WiFi Capture (tshark)** → watch Live Traffic + Alert Feed.

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
export DASHBOARD_API_KEY=demo-key
./scripts/run_dashboard.sh
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

## Alert policy (live Wi-Fi)

Live capture uses **LAN scan rules only** (`LIVE_ALERT_MODE = strict`) to avoid false alarms:

1. **Port scan** — `LAN_SCAN_ENABLED`: **8+ ports** to one LAN host in **12s** (`SCAN_BURST_*`), or **6+** if your PC is the victim. Label: **PortScan (nmap suspected)**, Method: **lan_scan**.
2. **ARP sweep** — `LAN_ARP_SWEEP_ENABLED`: **8+ ARP who-has** targets in **25s**. Label: **ARP sweep (host discovery)**, Method: **arp**.
3. **Simulate buttons** — Method: **demo** (not real LAN traffic).

ML does not raise DoS/R2L alerts on live Wi-Fi (unreliable on PCAP features). Tune in `config.py`: `SCAN_BURST_MIN_PORTS`, `SCAN_LOCAL_BURST_MIN_PORTS`, `LAN_ARP_MIN_HOSTS`.

### Test real nmap on Wi-Fi (authorized lab only)

1. Complete Wi-Fi capture setup above; **Load Model** → **Start WiFi Capture (tshark)**.
2. From another device on the **same LAN** (with permission), run:

   ```bash
   nmap -sS <target-ip-on-LAN>
   ```

3. Within ~12s expect:
   - Live Traffic: many TCP `[SYN]` rows toward the target.
   - Alert feed: **PortScan (nmap suspected)** with the scanner’s real source IP, Method **lan_scan**.
   - Capture banner: `LAN scan watch: ON`.

**Limits:** Detection is behavioral (many SYNs / ports), not a literal “nmap” signature. You may only see traffic that crosses the Wi-Fi adapter being captured; other clients’ traffic can be partially invisible on consumer Wi-Fi.

## Validation checklist

- [ ] `tshark -D` shows Wi-Fi interface on Windows
- [ ] Rolling PCAP files appear in `capture/incoming/`
- [ ] Dashboard shows **tshark active**
- [ ] `Flows Analysed` increases after traffic
- [ ] Alert feed shows plausible source IPs (not random 192.168.x.x demo IPs)
- [ ] **Live Traffic** table shows ARP/UDP rows matching Wireshark Info column
- [ ] `GET /api/traffic` returns packet rows with matching No/Time/Protocol/Length
- [ ] `GET /api/export_log` contains alert history
- [ ] Controlled `nmap -sS` produces **PortScan (nmap suspected)** with Method **lan_scan**
- [ ] `scripts/verify_lan_scan_detection.py` passes
- [ ] Banner shows **LAN scan watch: ON**

## Troubleshooting

### Run diagnostics (WSL)

```bash
cd ~/projects/IDS/fedaida_ids
./scripts/check_tshark_setup.sh
```

### tshark not working / empty `capture/incoming/`

| Symptom | Cause | Fix |
|---------|--------|-----|
| PowerShell tshark exits immediately | Not Admin, or Npcap not installed | Run PowerShell **as Administrator**; reinstall Wireshark with **Npcap** |
| `Cannot write to \\wsl$\...` | WSL stopped or wrong distro name | Start WSL (`wsl`); script auto-detects distro, or use `-UseLocalFolder` then copy PCAPs to WSL `incoming/` |
| Files in `processed/` but not `incoming/` | Ingest archived them (normal) | Keep **Windows tshark running**; new files must appear in `incoming/` while capturing |
| Weird names `wifi_%05d_00001...` | Old script used `wifi_%05d.pcapng` | Update script: now uses `wifi.pcapng` → `wifi_00001_....pcapng` |
| Capture starts then stops on Wi-Fi | Promiscuous mode unsupported | Do **not** pass `-Promiscuous` (default is OFF) |
| Dashboard ingest on, no packets | Scapy missing in WSL venv | `pip install scapy` in the venv you use for `dashboard/app.py` |
| Test without Windows | Replay old capture | `cp capture/processed/wifi_*.pcapng capture/incoming/` then click ingest (or restart tshark ingest) |

**Correct order:** (1) Windows `start_wifi_tshark_windows.ps1` **first** — leave it running. (2) WSL dashboard → **Start WiFi Capture (tshark)**. (3) Generate traffic (browse web / nmap test).

**Local Windows fallback** if WSL path fails:

```powershell
.\scripts\start_wifi_tshark_windows.ps1 -UseLocalFolder
```

Then in WSL:

```bash
cp /mnt/c/Users/$USER/FedAIDA/capture/incoming/*.pcapng ~/projects/IDS/fedaida_ids/capture/incoming/
```

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
