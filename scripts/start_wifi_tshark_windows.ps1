# FedAIDA-IDS - Start Windows Wi-Fi capture via tshark into WSL incoming folder
# Run in PowerShell as Administrator on the Windows host.
#
# Usage (from Windows path OR from \\wsl$\Ubuntu\...\fedaida_ids):
#   .\scripts\start_wifi_tshark_windows.ps1
#   .\scripts\start_wifi_tshark_windows.ps1 -Interface 5
#   .\scripts\start_wifi_tshark_windows.ps1 -UseLocalFolder
#
# Then in WSL: ./scripts/run_dashboard.sh -> Start WiFi Capture (tshark)

param(
    [int]$Interface = -1,
    [string]$WslDistro = "",
    [string]$ProjectSubPath = "home/balu/projects/IDS/fedaida_ids/capture/incoming",
    [int]$FileSizeKB = 512,
    [int]$RingFiles = 12,
    [switch]$Promiscuous,
    [switch]$NoPromiscuous,
    [switch]$UseLocalFolder
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
        if (Test-Path -LiteralPath $c) { return $c }
    }
    throw "tshark not found. Install Wireshark + Npcap from https://www.wireshark.org/download.html"
}

function ConvertTo-CleanWslDistroName {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return "Ubuntu" }
    $clean = $Raw -replace "`0", ""
    $clean = $clean -replace '\(Default\)', ''
    $clean = $clean.Trim()
    if ($clean -match '^([A-Za-z0-9_-]+)') {
        return $Matches[1]
    }
    return "Ubuntu"
}

function Get-DefaultWslDistroName {
    if ($WslDistro) {
        return (ConvertTo-CleanWslDistroName $WslDistro)
    }
    try {
        $lines = @(wsl.exe -l -q 2>$null)
        foreach ($line in $lines) {
            $name = ConvertTo-CleanWslDistroName $line
            if ($name) { return $name }
        }
    } catch { }
    return "Ubuntu"
}

function Resolve-IncomingDirectory {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $cwd = (Get-Location).ProviderPath

    if ($UseLocalFolder) {
        return (Join-Path $env:USERPROFILE "FedAIDA\capture\incoming")
    }

    # Running from \\wsl$\<distro>\...\fedaida_ids (recommended) - use relative path
    if ($projectRoot -match '^\\\\wsl\$\\') {
        return (Join-Path $projectRoot "capture\incoming")
    }
    if ($cwd -match '^\\\\wsl\$\\') {
        $fromCwd = Join-Path $cwd "capture\incoming"
        if ($cwd -match 'fedaida_ids') {
            return $fromCwd
        }
    }

    $distro = Get-DefaultWslDistroName
    return "\\wsl$\$distro\$ProjectSubPath"
}

function Ensure-DirectoryExists {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "Incoming directory path is empty"
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -LiteralPath $Path | Out-Null
        Write-Host "Created: $Path"
    }
}

$tshark = Get-TsharkPath
$distroName = Get-DefaultWslDistroName

Write-Host "Using tshark: $tshark"
Write-Host "WSL distro: $distroName"
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

$incoming = Resolve-IncomingDirectory
Write-Host "Capture folder: $incoming"

try {
    Ensure-DirectoryExists -Path $incoming
} catch {
    Write-Warning "Could not use capture folder: $incoming"
    Write-Warning $_.Exception.Message
    $incoming = Join-Path $env:USERPROFILE "FedAIDA\capture\incoming"
    Ensure-DirectoryExists -Path $incoming
    Write-Host "Using local fallback: $incoming"
    Write-Host "Copy PCAPs to WSL: cp /mnt/c/Users/$($env:USERNAME)/FedAIDA/capture/incoming/*.pcapng ~/projects/IDS/fedaida_ids/capture/incoming/"
}

$writeOk = $false
try {
    $probe = Join-Path $incoming ".tshark_write_test"
    [System.IO.File]::WriteAllText($probe, "ok")
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    $writeOk = $true
    Write-Host "Write test: OK"
} catch {
    Write-Warning "Write test failed for: $incoming"
    Write-Warning $_.Exception.Message
}

if (-not $writeOk) {
    $incoming = Join-Path $env:USERPROFILE "FedAIDA\capture\incoming"
    Ensure-DirectoryExists -Path $incoming
    Write-Host "Falling back to: $incoming"
}

$outBase = Join-Path $incoming "wifi.pcapng"
Write-Host "Writing rolling captures to: $outBase (ring ${FileSizeKB}KB x $RingFiles)"
Write-Host "Press Ctrl+C to stop capture."
Write-Host ""
Write-Host "Tip: run PowerShell as Administrator if capture fails."
Write-Host ""

$tsharkArgs = @(
    "-i", "$Interface",
    "-b", "filesize:$FileSizeKB",
    "-b", "files:$RingFiles",
    "-w", $outBase
)

# Promiscuous helps see other devices scanning on the same Wi-Fi (when AP allows it)
$usePromisc = $Promiscuous -or (-not $NoPromiscuous)
if ($usePromisc) {
    Write-Host "Promiscuous mode: ON (see more LAN scan traffic between devices)"
    $tsharkArgs = @("-o", "capture.promiscuous_mode:TRUE") + $tsharkArgs
} else {
    Write-Host "Promiscuous mode: OFF (only traffic to/from this PC)"
}

& $tshark @tsharkArgs
