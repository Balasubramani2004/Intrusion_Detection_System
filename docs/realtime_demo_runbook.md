# Realtime IDS Demo Runbook

Repeatable rehearsal for **real Wi-Fi capture** (primary) and **synthetic fallback**.

See also: [`wireshark_wifi_capture.md`](wireshark_wifi_capture.md), [`datasets_download.md`](datasets_download.md)

---

## 1) Start dashboard securely

```bash
cd /home/balu/projects/IDS/fedaida_ids
source .venv/bin/activate
export DASHBOARD_API_KEY="demo-key"
export DASHBOARD_CORS_ORIGINS="http://localhost:5000,http://127.0.0.1:5000"
python dashboard/app.py
```

Open `http://localhost:5000` and hard-refresh (`Ctrl+Shift+R`).

---

## 2) Operator UI setup

- Click **Load model**
- Click **Start Wi-Fi capture** (after Windows tshark script is running)

---

## 3) Real Wi-Fi rehearsal (viva path)

### Windows (host)

```powershell
cd \\wsl$\Ubuntu\home\balu\projects\IDS\fedaida_ids
.\scripts\start_wifi_tshark_windows.ps1
# or: .\scripts\start_wifi_tshark_windows.ps1 -Interface 5
```

### WSL (dashboard)

- Click **Start WiFi Capture (tshark)**
- Confirm top banner: green, **Packets buffered** increasing, **Last packet** time updating

### Side-by-side with Wireshark

| Check | Wireshark | FedAIDA Live Traffic |
|-------|-----------|----------------------|
| ARP | Who has / is at | Same **Info** string |
| UDP/TCP | sport → dport, Len | Same ports and **Length** |
| Time | Local PC time | Local time (after timezone fix) |
| Detection | N/A | **Normal** or attack after 3+ pkts/flow |

Validation API:

```bash
curl -s 'http://127.0.0.1:5000/api/traffic?limit=5' | python3 -m json.tool
curl -s http://127.0.0.1:5000/api/status | python3 -m json.tool
```

### Without Windows tshark (PCAP upload)

```bash
curl -X POST http://127.0.0.1:5000/api/capture/tshark/upload \
  -H "X-API-Key: demo-key" \
  -F "file=@/path/to/capture.pcapng"
```

---

## 4) Response action rehearsal

- Teammate runs `nmap -sS <your-wifi-ip>` toward your laptop
- Verify alert in **Live Alert Feed** (Destination / Protocol / Length when from real capture)
- Verify **Blocked IPs** when confidence > 95%
- **Unblock** single IP and **Unblock All**

### 5b) LAN port-scan detection (anyone on same Wi-Fi)

With **Start WiFi Capture (tshark)** active and model loaded:

1. Note **your laptop Wi-Fi IP** (e.g. `192.168.1.42`).
2. Run `scripts/verify_lan_scan_detection.py` in WSL (logic check, no nmap).
3. Teammate (lab permission only): `nmap -sS <your-laptop-ip>`
4. Within **~12 seconds** expect:
   - Live Traffic: many TCP `[SYN]` rows to your IP
   - Alert: **PortScan (nmap suspected)**, Method **lan_scan**, Source = scanner IP
   - Banner: `LAN scan watch: ON (this PC: …)`
5. For host discovery: `nmap -sn 192.168.1.0/24` may trigger **ARP sweep** (Method **arp**).

Scans between two *other* devices may not appear if the AP uses client isolation.

---

## 6) Export evidence

```bash
curl -s http://127.0.0.1:5000/api/export_log -H "X-API-Key: demo-key" | python3 -m json.tool
```

Save JSON for viva audit trail.

---

## Viva day checklist

- [ ] Model loaded (green **Model Loaded**)
- [ ] Windows tshark running OR PCAP uploaded
- [ ] **Start Wi-Fi capture** active (top bar: Wi-Fi capture on)
- [ ] Live Traffic rows match Wireshark for same moment
- [ ] Real `nmap -sS` triggers **PortScan (nmap suspected)** when teammate scans your IP
- [ ] `GET /api/export_log` saved

---

## Synthetic fallback script (no live traffic)

```bash
python3 - <<'PY'
import json, urllib.request
base='http://127.0.0.1:5000'
headers={'Content-Type':'application/json','X-API-Key':'demo-key'}

def req(path, method='GET', body=None):
    data=None if body is None else json.dumps(body).encode()
    r=urllib.request.Request(base+path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(r, timeout=10) as resp:
        return json.loads(resp.read().decode())

print(req('/api/load_model','POST',{'dataset':'nsl_kdd','n_classes':5}))
for _ in range(3):
    print(req('/api/simulate_attack','POST',{'type':'PortScan','src_ip':'192.168.1.250'}))
print('blocked', req('/api/blocked'))
print(req('/api/unblock_all','POST'))
print('export keys', list(req('/api/export_log').keys()))
PY
```
