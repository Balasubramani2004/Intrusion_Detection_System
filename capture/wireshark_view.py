"""
Wireshark-compatible packet summary for dashboard display.
Maps Scapy packets to No / Time / Source / Destination / Protocol / Length / Info.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import time as _time

try:
    from scapy.all import ARP, Ether, ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    try:
        from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6ND_NS
    except ImportError:
        ICMPv6ND_RA = ICMPv6ND_NS = None  # type: ignore
    SCAPY_LAYERS = True
except ImportError:
    SCAPY_LAYERS = False
    ARP = Ether = ICMP = IP = TCP = UDP = IPv6 = None  # type: ignore
    ICMPv6ND_RA = ICMPv6ND_NS = None  # type: ignore


def _format_time_utc(ts: Optional[float] = None) -> str:
    """UTC Wireshark-style string (legacy; UI should prefer time_epoch + browser local)."""
    dt = (
        datetime.fromtimestamp(ts, tz=timezone.utc)
        if ts is not None
        else datetime.now(timezone.utc)
    )
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond:06d}"


def packet_to_row(pkt, packet_no: int, epoch: Optional[float] = None) -> dict[str, Any]:
    """
    Build a Wireshark-style row dict from a Scapy packet.
    """
    length = len(pkt)
    ts = epoch if epoch is not None else _time.time()
    row = {
        "no": packet_no,
        "time": _format_time_utc(ts),
        "time_epoch": float(ts),
        "source": "",
        "destination": "",
        "protocol": "",
        "length": length,
        "info": "",
        "src_ip": "",
        "dst_ip": "",
        "src_port": None,
        "dst_port": None,
        "detection": "",
        "confidence": None,
        "severity": "",
        "is_attack": False,
    }

    if not SCAPY_LAYERS:
        row["info"] = "Scapy layers unavailable"
        return row

    # ARP
    if ARP in pkt:
        arp = pkt[ARP]
        row["protocol"] = "ARP"
        row["source"] = getattr(arp, "hwsrc", None) or (
            pkt[Ether].src if Ether in pkt else ""
        )
        eth_dst = pkt[Ether].dst if Ether in pkt else ""
        hwdst = getattr(arp, "hwdst", None) or eth_dst
        if hwdst in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", ""):
            row["destination"] = "Broadcast"
        else:
            row["destination"] = hwdst
        if getattr(arp, "op", 0) == 1:
            row["info"] = (
                f"Who has {arp.pdst}? Tell {arp.psrc}"
                if getattr(arp, "pdst", None) and getattr(arp, "psrc", None)
                else "ARP Request"
            )
        elif getattr(arp, "op", 0) == 2:
            row["info"] = (
                f"{arp.psrc} is at {arp.hwsrc}"
                if getattr(arp, "psrc", None) and getattr(arp, "hwsrc", None)
                else "ARP Reply"
            )
        else:
            row["info"] = f"ARP op={getattr(arp, 'op', '?')}"
        return row

    # IPv6
    if IPv6 is not None and IPv6 in pkt:
        row["protocol"] = "IPv6"
        row["source"] = pkt[IPv6].src
        row["destination"] = pkt[IPv6].dst
        row["src_ip"] = pkt[IPv6].src
        row["dst_ip"] = pkt[IPv6].dst
        nh = int(pkt[IPv6].nh)
        if ICMPv6ND_RA is not None and ICMPv6ND_RA in pkt:
            row["protocol"] = "ICMPv6"
            row["info"] = "Router advertisement"
        elif ICMPv6ND_NS is not None and ICMPv6ND_NS in pkt:
            row["protocol"] = "ICMPv6"
            row["info"] = "Neighbor solicitation"
        elif nh == 58:
            row["protocol"] = "ICMPv6"
            row["info"] = "ICMPv6"
        elif nh == 6 and TCP in pkt:
            row["protocol"] = "TCP"
            row["info"] = (
                f"{pkt[TCP].sport} → {pkt[TCP].dport} "
                f"Seq={pkt[TCP].seq} Ack={pkt[TCP].ack}"
            )
            row["src_port"] = int(pkt[TCP].sport)
            row["dst_port"] = int(pkt[TCP].dport)
        elif nh == 17 and UDP in pkt:
            row["protocol"] = "UDP"
            row["info"] = f"{pkt[UDP].sport} → {pkt[UDP].dport} Len={length}"
            row["src_port"] = int(pkt[UDP].sport)
            row["dst_port"] = int(pkt[UDP].dport)
        else:
            row["info"] = f"IPv6 nh={nh}"
        return row

    # IPv4
    if IP in pkt:
        row["source"] = pkt[IP].src
        row["destination"] = pkt[IP].dst
        row["src_ip"] = pkt[IP].src
        row["dst_ip"] = pkt[IP].dst

        if TCP in pkt:
            row["protocol"] = "TCP"
            sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            row["src_port"] = sport
            row["dst_port"] = dport
            flags = pkt[TCP].sprintf("%TCP.flags%")
            row["info"] = f"{sport} → {dport} [{flags}] Seq={pkt[TCP].seq} Ack={pkt[TCP].ack}"
        elif UDP in pkt:
            row["protocol"] = "UDP"
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            row["src_port"] = sport
            row["dst_port"] = dport
            row["info"] = f"{sport} → {dport} Len={length}"
        elif ICMP in pkt:
            row["protocol"] = "ICMP"
            row["info"] = pkt[ICMP].sprintf("%ICMP.type% %ICMP.code%")
        else:
            row["protocol"] = f"IP proto {pkt[IP].proto}"
            row["info"] = f"proto={pkt[IP].proto}"
        return row

    # Ethernet fallback
    if Ether in pkt:
        row["protocol"] = "Ethernet"
        row["source"] = pkt[Ether].src
        row["destination"] = pkt[Ether].dst
        row["info"] = f"Type 0x{pkt[Ether].type:04x}"
        return row

    row["protocol"] = "Unknown"
    row["info"] = "Unknown frame"
    return row
