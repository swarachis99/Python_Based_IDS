import queue
import threading
import logging
import json
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from sklearn.ensemble import IsolationForest
import numpy as np


# =============================================
# Module 1: Packet Capture
# =============================================
class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="Ethernet 4"):
        def capture_thread():
            try:
                sniff(iface=interface, prn=self.packet_callback, store=0,
                      stop_filter=lambda _: self.stop_capture.is_set())
            except Exception as e:
                print(f"[!] Error capturing on {interface}: {e}")
                print("[*] Trying to capture on all interfaces...")
                sniff(prn=self.packet_callback, store=0,
                      stop_filter=lambda _: self.stop_capture.is_set())

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()


# =============================================
# Module 2: Traffic Analysis
# =============================================
class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            flow_key = (ip_src, ip_dst, port_src, port_dst)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)
        return None

    def extract_features(self, packet, stats):
        return {
            'packet_size': len(packet),
            'flow_duration': stats['last_time'] - stats['start_time'],
            'packet_rate': stats['packet_count'] / max(1, (stats['last_time'] - stats['start_time'])),
            'byte_rate': stats['byte_count'] / max(1, (stats['last_time'] - stats['start_time'])),
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }


# =============================================
# Module 3: Detection Engine
# =============================================
class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.is_fitted = False

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                        features['tcp_flags'] == 2 and
                        features['packet_rate'] > 10  # lowered from 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                        features['packet_size'] < 100 and
                        features['packet_rate'] > 5   # lowered from 50
                )
            }
        }

    def train_anomaly_detector(self, normal_traffic_data=None):
        if normal_traffic_data is None:
            # Synthetic normal traffic data for training
            normal_traffic_data = np.array([
                [100, 10, 500], [200, 15, 800], [300, 20, 1200],
                [150, 12, 600], [250, 18, 1000], [180, 14, 700],
                [120, 8, 400], [350, 25, 1500], [400, 30, 2000],
                [80, 5, 300], [220, 16, 900], [280, 22, 1300],
                [160, 13, 650], [320, 28, 1800], [90, 6, 350],
            ])

        self.anomaly_detector.fit(normal_traffic_data)
        self.is_fitted = True
        print("[*] Anomaly detector trained successfully!")

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Anomaly-based detection
        if not self.is_fitted:
            self.train_anomaly_detector()

        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])

        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        if anomaly_score < -0.7:  # raised threshold: only flag stronger anomalies
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score,
                'confidence': min(1.0, abs(anomaly_score))
            })

        return threats


# =============================================
# Module 4: Alert System
# =============================================
class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8:
            self.logger.critical(f"High confidence threat detected: {json.dumps(alert)}")
            # Print to console for immediate visibility
            print(f"\n[!] CRITICAL: High confidence threat from {packet_info.get('source_ip')}!")


# =============================================
# Module 5: Main IDS System
# =============================================
def get_default_interface():
    try:
        from scapy.arch import get_if_list
        interfaces = get_if_list()

        print(f"[*] Available interfaces: {interfaces}")

        preferred = ["Ethernet 4", "Wi-Fi", "Ethernet0", "Ethernet", "eth0", "wlan0"]

        for pref in preferred:
            if pref in interfaces:
                print(f"[*] Using interface: {pref}")
                return pref

        for iface in interfaces:
            if "Loopback" not in iface and "lo" not in iface:
                print(f"[*] Using interface: {iface}")
                return iface

        return None
    except Exception as e:
        print(f"[!] Error detecting interface: {e}")
        return None


class IntrusionDetectionSystem:
    def __init__(self, interface="Ethernet 4"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.interface = interface
        # Auto-train anomaly detector
        self.detection_engine.train_anomaly_detector()

    def start(self):
        if self.interface is None:
            print("[!] No interface found! Please connect to a network.")
            return

        print(f"[*] Starting IDS on interface: {self.interface}")
        self.packet_capture.start_capture(self.interface)

        try:
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    features = self.traffic_analyzer.analyze_packet(packet)

                    if features:
                        threats = self.detection_engine.detect_threats(features)

                        for threat in threats:
                            packet_info = {
                                'source_ip': packet[IP].src,
                                'destination_ip': packet[IP].dst,
                                'source_port': packet[TCP].sport,
                                'destination_port': packet[TCP].dport
                            }
                            self.alert_system.generate_alert(threat, packet_info)

                except queue.Empty:
                    continue

        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt detected. Stopping IDS...")
            self.packet_capture.stop()
            print("[*] IDS stopped.")


# =============================================
# Run the IDS
# =============================================
if __name__ == "__main__":
    interface = get_default_interface()

    if interface is None:
        print("[!] Could not find network interface.")
        print("[*] Please connect to a network and run again.")
    else:
        ids = IntrusionDetectionSystem(interface=interface)
        ids.start()