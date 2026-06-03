"""Local LAN IP discovery for on-network scan detection."""
from __future__ import annotations

import ipaddress
import socket
from typing import Set


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
