"""Wireshark-style packet row formatting."""
import pytest

pytest.importorskip("scapy")
from scapy.all import ARP, Ether, IP, UDP
from capture.wireshark_view import packet_to_row


def test_arp_request_info():
    pkt = (
        Ether(dst="6c:2f:80:ca:ba:de", src="d8:07:b6:ec:03:ed")
        / ARP(
            op=1,
            hwsrc="d8:07:b6:ec:03:ed",
            hwdst="6c:2f:80:ca:ba:de",
            psrc="192.168.0.1",
            pdst="192.168.0.111",
        )
    )
    row = packet_to_row(pkt, 1)
    assert row["protocol"] == "ARP"
    assert "Who has 192.168.0.111" in row["info"]
    assert "Tell 192.168.0.1" in row["info"]


def test_udp_ipv4_info():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=51449, dport=443)
    row = packet_to_row(pkt, 2)
    assert row["protocol"] == "UDP"
    assert "51449" in row["info"] and "443" in row["info"]
