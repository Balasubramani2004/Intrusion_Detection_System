"""
FedAIDA-IDS — Live Packet Capture
Real-time network traffic capture and feature extraction.
Used for live demo on college network.
Requires: sudo python3 capture/live_capture.py
"""
import os, sys, time, logging, pickle, socket, struct
from collections import defaultdict
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np

logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, IP, TCP, UDP, ARP
    try:
        from scapy.layers.inet6 import IPv6
    except ImportError:
        IPv6 = None  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IPv6 = None  # type: ignore
    logger.warning("Scapy not available — live capture disabled. "
                   "Run: pip install scapy")

from capture.wireshark_view import packet_to_row

try:
    from config import SEQUENCE_LEN, MODELS_DIR, CONFIDENCE_HIGH
except:
    SEQUENCE_LEN = 10; MODELS_DIR = 'saved_models'; CONFIDENCE_HIGH = 0.90

FLOW_TIMEOUT  = 5.0   # seconds before a flow is finalised


class FlowRecord:
    """Tracks statistics for a single network flow (5-tuple)."""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.key = (src_ip, dst_ip, src_port, dst_port, protocol)
        self.src_ip = src_ip; self.dst_ip = dst_ip
        self.src_port = src_port; self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time()
        self.last_time  = time.time()
        self.pkt_count  = 0
        self.byte_count = 0
        self.fwd_pkts   = 0; self.bwd_pkts = 0
        self.fwd_bytes  = 0; self.bwd_bytes = 0
        self.pkt_lens   = []; self.iat = []
        self.syn_count  = 0; self.fin_count = 0
        self.rst_count  = 0; self.psh_count = 0
        self.ack_count  = 0; self.urg_count = 0
        self._last_pkt_time = time.time()

    def add_packet(self, pkt_len, flags=0, direction='fwd'):
        now = time.time()
        self.iat.append(now - self._last_pkt_time)
        self._last_pkt_time = now
        self.last_time = now
        self.pkt_count += 1
        self.byte_count += pkt_len
        self.pkt_lens.append(pkt_len)
        if direction == 'fwd':
            self.fwd_pkts += 1; self.fwd_bytes += pkt_len
        else:
            self.bwd_pkts += 1; self.bwd_bytes += pkt_len
        if flags:
            if flags & 0x02: self.syn_count += 1
            if flags & 0x01: self.fin_count += 1
            if flags & 0x04: self.rst_count += 1
            if flags & 0x08: self.psh_count += 1
            if flags & 0x10: self.ack_count += 1
            if flags & 0x20: self.urg_count += 1

    def to_features(self):
        """Extract 41 NSL-KDD-compatible features from flow."""
        duration = max(self.last_time - self.start_time, 1e-6)
        lens = np.array(self.pkt_lens) if self.pkt_lens else np.array([0])
        iats = np.array(self.iat[1:]) if len(self.iat) > 1 else np.array([0])

        features = [
            duration,
            self.protocol,      # protocol_type encoded
            self.dst_port % 100,# service proxy
            1.0,                # flag proxy
            self.fwd_bytes,     # src_bytes
            self.bwd_bytes,     # dst_bytes
            0,                  # land
            0,                  # wrong_fragment
            0,                  # urgent
            int(self.psh_count > 5),  # hot
            0,                  # num_failed_logins
            0,                  # logged_in
            0,                  # num_compromised
            0,                  # root_shell
            0, 0, 0, 0, 0, 0, 0, 0,  # other content features
            self.pkt_count,     # count
            self.pkt_count,     # srv_count
            # Statistical features
            self.syn_count / (self.pkt_count + 1e-6),       # serror_rate
            self.syn_count / (self.pkt_count + 1e-6),       # srv_serror_rate
            self.rst_count / (self.pkt_count + 1e-6),       # rerror_rate
            self.rst_count / (self.pkt_count + 1e-6),       # srv_rerror_rate
            self.fwd_pkts / (self.pkt_count + 1e-6),        # same_srv_rate
            self.bwd_pkts / (self.pkt_count + 1e-6),        # diff_srv_rate
            min(self.byte_count / (duration + 1e-6), 1e6),  # srv_diff_host_rate
            min(self.pkt_count, 511),                        # dst_host_count
            min(self.pkt_count, 511),                        # dst_host_srv_count
            self.fwd_pkts / (self.pkt_count + 1e-6),        # same_srv_rate2
            self.bwd_pkts / (self.pkt_count + 1e-6),        # diff_srv_rate2
            self.syn_count / (self.pkt_count + 1e-6),       # same_src_port_rate
            0.0,                                             # srv_diff_host_rate2
            self.syn_count / (self.pkt_count + 1e-6),       # dst_host_serror_rate
            self.syn_count / (self.pkt_count + 1e-6),       # dst_host_srv_serror_rate
            self.rst_count / (self.pkt_count + 1e-6),       # dst_host_rerror_rate
            self.rst_count / (self.pkt_count + 1e-6),       # dst_host_srv_rerror_rate
        ]
        return np.array(features[:41], dtype=np.float32)

    @property
    def is_expired(self):
        return (time.time() - self.last_time) > FLOW_TIMEOUT


class LiveCapture:
    """
    Live packet capture engine.
    Captures → extracts features → classifies → alerts dashboard.
    """
    def __init__(self, interface=None, on_alert_callback=None,
                 on_packet_callback=None, label_names=None, scaler=None):
        self.interface  = interface
        self.callback   = on_alert_callback
        self.on_packet_callback = on_packet_callback
        self.label_names= label_names or ['Normal','DoS','Probe','R2L','U2R']
        self.scaler     = scaler
        self.flows      = {}
        self.flow_buffer= []   # completed flows awaiting classification
        self.running    = False
        self.stats      = {'packets': 0, 'flows': 0, 'alerts': 0}

        # Try to load scaler
        if self.scaler is None:
            scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info("Scaler loaded for live capture")

    def _get_flow_key(self, pkt):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = int(pkt[IP].proto)
            sport = int(pkt[TCP].sport) if TCP in pkt else (int(pkt[UDP].sport) if UDP in pkt else 0)
            dport = int(pkt[TCP].dport) if TCP in pkt else (int(pkt[UDP].dport) if UDP in pkt else 0)
        elif IPv6 is not None and IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            proto = int(pkt[IPv6].nh)
            sport = int(pkt[TCP].sport) if TCP in pkt else (int(pkt[UDP].sport) if UDP in pkt else 0)
            dport = int(pkt[TCP].dport) if TCP in pkt else (int(pkt[UDP].dport) if UDP in pkt else 0)
        else:
            return None
        if src < dst:
            return (src, dst, sport, dport, proto)
        return (dst, src, dport, sport, proto)

    def _emit_packet_row(self, pkt):
        self.stats['packets'] += 1
        epoch = float(pkt.time) if hasattr(pkt, 'time') else None
        row = packet_to_row(pkt, self.stats['packets'], epoch=epoch)
        if self.on_packet_callback:
            try:
                self.on_packet_callback(row)
            except Exception as e:
                logger.debug("Packet callback error: %s", e)

    def _process_packet(self, pkt):
        self._emit_packet_row(pkt)

        if IP not in pkt and not (IPv6 is not None and IPv6 in pkt):
            return

        key = self._get_flow_key(pkt)
        if key is None:
            return

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        else:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        if key not in self.flows:
            sport = int(pkt[TCP].sport) if TCP in pkt else (int(pkt[UDP].sport) if UDP in pkt else 0)
            dport = int(pkt[TCP].dport) if TCP in pkt else (int(pkt[UDP].dport) if UDP in pkt else 0)
            if TCP in pkt:
                proto = 6
            elif UDP in pkt:
                proto = 17
            elif IP in pkt:
                proto = int(pkt[IP].proto)
            else:
                proto = int(pkt[IPv6].nh)
            self.flows[key] = FlowRecord(src_ip, dst_ip, sport, dport, proto)

        flow = self.flows[key]
        pkt_len = len(pkt)
        flags = int(pkt[TCP].flags) if TCP in pkt else 0
        direction = 'fwd' if src_ip == flow.src_ip else 'bwd'
        flow.add_packet(pkt_len, flags, direction)

        expired = [k for k, f in self.flows.items() if f.is_expired]
        for k in expired:
            self._finalise_flow(self.flows.pop(k))

    def _finalise_flow(self, flow):
        """Extract features and classify completed flow."""
        self.stats['flows'] += 1
        features = flow.to_features()

        if self.scaler is not None:
            try:
                features = self.scaler.transform([features])[0]
            except Exception as e:
                logger.debug(f"Scaler error: {e}")

        proto_name = 'TCP' if flow.protocol == 6 else ('UDP' if flow.protocol == 17 else str(flow.protocol))
        self.flow_buffer.append({
            'features': features,
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'protocol': proto_name,
            'pkt_count': flow.pkt_count,
            'bytes': flow.byte_count,
            'duration': round(flow.last_time - flow.start_time, 3),
            'timestamp': datetime.now().isoformat(),
        })

        if self.callback:
            try:
                self.callback(self.flow_buffer[-1])
            except Exception as e:
                logger.debug(f"Callback error: {e}")

    def start(self, interface=None, packet_count=0):
        """Start live capture. Requires root/sudo."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not installed. Run: pip install scapy")
            return

        iface = interface or self.interface
        self.running = True
        logger.info(f"Starting live capture on {iface or 'default interface'}...")
        logger.info("Press Ctrl+C to stop")

        try:
            sniff(iface=iface, prn=self._process_packet,
                  count=packet_count, store=False,
                  stop_filter=lambda _: not self.running)
        except PermissionError:
            logger.error("PERMISSION DENIED. Run with sudo: sudo python3 capture/live_capture.py")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.running = False
            # Finalise remaining flows
            for flow in self.flows.values():
                self._finalise_flow(flow)
            logger.info(f"Capture stopped. Stats: {self.stats}")

    def stop(self):
        self.running = False


def pcap_replay(pcap_file, on_flow_callback, scaler=None, label_names=None):
    """
    Replay a saved PCAP file for demo without needing a live network.
    Great for viva demonstration without requiring a second machine.
    """
    if not SCAPY_AVAILABLE:
        logger.error("Scapy required for PCAP replay")
        return

    from scapy.all import rdpcap
    logger.info(f"Replaying PCAP: {pcap_file}")
    capture = LiveCapture(on_alert_callback=on_flow_callback,
                          label_names=label_names, scaler=scaler)

    pkts = rdpcap(pcap_file)
    for pkt in pkts:
        capture._process_packet(pkt)

    # Finalise all flows
    for flow in capture.flows.values():
        capture._finalise_flow(flow)

    logger.info(f"Replay complete. Flows processed: {capture.stats['flows']}")
    return capture.flow_buffer


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', default=None, help='Network interface')
    parser.add_argument('--count', '-c', type=int, default=0, help='Packet count (0=infinite)')
    args = parser.parse_args()

    def alert_handler(flow_info):
        print(f"[FLOW] {flow_info['src_ip']} → {flow_info['dst_ip']}:{flow_info['dst_port']} "
              f"| {flow_info['pkt_count']} pkts | {flow_info['bytes']} bytes")

    capture = LiveCapture(on_alert_callback=alert_handler)
    capture.start(interface=args.interface, packet_count=args.count)
