from scapy.all import IP, TCP
from ids_system import IntrusionDetectionSystem, TrafficAnalyzer

def test_ids():
    print("[*] Starting IDS Simulation Test...")

    # Simulate different types of traffic
    test_packets = [
        # Normal traffic (should NOT trigger alerts)
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),

        # SYN Flood attack simulation (SHOULD trigger alert)
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S"),

        # Port scan simulation (SHOULD trigger alert)
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]

    # Initialize the analyzer
    analyzer = TrafficAnalyzer()
    ids_system = IntrusionDetectionSystem()

    for i, packet in enumerate(test_packets, 1):
        print(f"\n[*] Processing packet {i}: {packet.summary()}")
        features = analyzer.analyze_packet(packet)

        if features:
            threats = ids_system.detection_engine.detect_threats(features)
            if threats:
                print(f"[!] ⚠️  Threats detected: {threats}")
            else:
                print("[✓] ✅ No threats detected.")
        else:
            print("[-] Packet does not contain IP/TCP layers. Skipping.")

    print("\n[*] IDS Simulation Test Complete.")

if __name__ == "__main__":
    test_ids()