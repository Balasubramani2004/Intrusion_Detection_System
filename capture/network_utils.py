"""Local LAN IP discovery for on-network scan detection."""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import subprocess
from typing import Set

logger = logging.getLogger(__name__)


def is_private_lan_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private and not addr.is_loopback
    except ValueError:
        return False


def get_local_ipv4_addresses() -> Set[str]:
    """Collect IPv4 addresses on this host (WSL + common paths)."""
    found: Set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if is_private_lan_ip(ip):
                found.add(ip)
    except OSError:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if is_private_lan_ip(ip):
            found.add(ip)
    except OSError:
        pass

    try:
        import netifaces  # type: ignore
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for entry in addrs:
                ip = entry.get("addr")
                if ip and is_private_lan_ip(ip):
                    found.add(ip)
    except ImportError:
        pass
    except Exception:
        pass

    return found


def _powershell_executables() -> list[str]:
    """WSL often lacks powershell.exe on PATH; use the Windows install path."""
    windir = os.environ.get("WINDIR", "/mnt/c/Windows")
    candidates = [
        "powershell.exe",
        os.path.join(windir, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    ]
    seen: set[str] = set()
    out: list[str] = []
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        if path == "powershell.exe" or os.path.isfile(path):
            out.append(path)
    return out or ["powershell.exe"]


def _run_powershell(command: str, timeout: float = 10.0) -> subprocess.CompletedProcess | None:
    for exe in _powershell_executables():
        try:
            return subprocess.run(
                [exe, "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.debug("PowerShell via %s failed: %s", exe, e)
    return None


def get_windows_wifi_ipv4_addresses() -> Set[str]:
    """
    Read the Windows host Wi-Fi IPv4 from WSL (college laptop path).
    DHCP may assign a new address each day — refreshed when the dashboard starts.
    """
    found: Set[str] = set()
    ps = (
        "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.InterfaceAlias -match 'Wi-Fi|Wireless|WLAN' } | "
        "Select-Object -ExpandProperty IPAddress"
    )
    proc = _run_powershell(ps)
    if proc is not None:
        for line in (proc.stdout or "").splitlines():
            ip = line.strip()
            if is_private_lan_ip(ip):
                found.add(ip)
    if found:
        return found

    # Fallback: parse `ipconfig` when Get-NetIPAddress is unavailable
    proc = _run_powershell("ipconfig")
    if proc is None:
        return found
    in_wifi = False
    for line in (proc.stdout or "").splitlines():
        low = line.lower()
        if "wireless lan adapter wi-fi" in low or "wireless lan adapter wlan" in low:
            in_wifi = True
            continue
        if in_wifi and line.strip().startswith("Wireless LAN adapter"):
            break
        if in_wifi and "ipv4" in low:
            parts = line.split(":", 1)
            if len(parts) == 2:
                ip = parts[1].strip().split("(")[0].strip()
                if is_private_lan_ip(ip):
                    found.add(ip)
                    in_wifi = False
    return found


def merge_local_ips(
    detected: Set[str] | None = None,
    whitelist: Set[str] | None = None,
    windows_wifi: Set[str] | None = None,
) -> Set[str]:
    """Union of WSL-detected, Windows Wi-Fi, and configured LAN IPs."""
    out: Set[str] = set(detected or ())
    for ip in windows_wifi or ():
        ip = (ip or "").strip()
        if ip and is_private_lan_ip(ip):
            out.add(ip)
    for ip in whitelist or ():
        ip = (ip or "").strip()
        if ip and is_private_lan_ip(ip):
            out.add(ip)
    return out
