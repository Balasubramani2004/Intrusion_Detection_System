# FedAIDA-IDS — Start Windows Wi-Fi capture via tshark into WSL incoming folder
# Run in PowerShell (Admin recommended) on the Windows host.
#
# Usage:
#   .\scripts\start_wifi_tshark_windows.ps1
#   .\scripts\start_wifi_tshark_windows.ps1 -Interface 5
#
# Then in WSL: start dashboard and POST /api/capture/tshark/start (or use UI button).

param(
    [int]$Interface = -1,
    [string]$WslDistro = "Ubuntu",
    [string]$ProjectSubPath = "home/balu/projects/IDS/fedaida_ids/capture/incoming",
    [int]$FileSizeKB = 512,
    [int]$RingFiles = 12
)

$ErrorActionPreference = "Stop"

function Get-TsharkPath {
    $t = Get-Command tshark -ErrorAction SilentlyContinue
    if ($t) { return $t.Source }
    $candidates = @(
        "${env:ProgramFiles}\Wireshark\tshark.exe",
        "${env:ProgramFiles(x86)}\Wireshark\tshark.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    throw "tshark not found. Install Wireshark from https://www.wireshark.org/download.html"
}

$tshark = Get-TsharkPath
Write-Host "Using tshark: $tshark"
Write-Host ""
Write-Host "Available interfaces (use -Interface <number>):"
& $tshark -D
Write-Host ""

if ($Interface -lt 0) {
    $wifi = (& $tshark -D 2>&1) | Where-Object { $_ -match 'Wi-?Fi|Wireless|WLAN' } | Select-Object -First 1
    if ($wifi -match '^\s*(\d+)\.') {
        $Interface = [int]$Matches[1]
        Write-Host "Auto-selected Wi-Fi interface: $Interface ($wifi)"
    } else {
        Write-Host "Could not auto-detect Wi-Fi. Re-run with: .\start_wifi_tshark_windows.ps1 -Interface <n>"
        exit 1
    }
}

$incoming = "\\wsl$\$WslDistro\$ProjectSubPath"
if (-not (Test-Path $incoming)) {
    New-Item -ItemType Directory -Force -Path $incoming | Out-Null
    Write-Host "Created: $incoming"
}

$outPattern = Join-Path $incoming "wifi_%05d.pcapng"
Write-Host "Writing rolling captures to: $outPattern"
Write-Host "Ring: ${FileSizeKB}KB x $RingFiles files"
Write-Host "Press Ctrl+C to stop capture."
Write-Host ""

# Rolling capture: new file every FileSizeKB, keep RingFiles files
& $tshark `
    -i $Interface `
    -b "filesize:$FileSizeKB" `
    -b "files:$RingFiles" `
    -w $outPattern
