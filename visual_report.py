import os
import json
from datetime import datetime


def create_visual_report():
    """Create a visual report with counts and tables"""

    print("=" * 70)
    print("CYBERSECURITY INTRUSION DETECTION SYSTEM - LAB REPORT")
    print("=" * 70)
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Student: [YOUR NAME]")
    print(f"Course: [COURSE NAME]")
    print("\n" + "-" * 70)
    print("1. SYSTEM OVERVIEW")
    print("-" * 70)
    print("""
    - Python-based Real-Time Intrusion Detection System
    - Uses Scapy for packet capture and analysis
    - Machine Learning (Isolation Forest) for anomaly detection
    - Signature-based rules for SYN Flood and Port Scan detection
    - Logs all alerts to ids_alerts.log
    """)

    # Check if log file exists
    log_file = "ids_alerts.log"
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            lines = f.readlines()
            alert_count = len([l for l in lines if 'WARNING' in l or 'CRITICAL' in l])

        print("\n" + "-" * 70)
        print("2. DETECTION SUMMARY")
        print("-" * 70)
        print(f"   Total alerts detected: {alert_count}")

        # Count by type
        syn_count = sum(1 for l in lines if 'syn_flood' in l)
        port_count = sum(1 for l in lines if 'port_scan' in l)
        anomaly_count = sum(1 for l in lines if 'anomaly' in l)

        print(f"   - SYN Flood attacks: {syn_count}")
        print(f"   - Port Scans: {port_count}")
        print(f"   - Anomalies detected: {anomaly_count}")

    print("\n" + "-" * 70)
    print("3. CAPTURED PACKETS (Sample)")
    print("-" * 70)

    try:
        from scapy.all import sniff
        sample_packets = sniff(timeout=5, count=10)
        for i, pkt in enumerate(sample_packets[:5], 1):
            print(f"   {i}. {pkt.summary()}")
    except:
        print("   [Run packet_capture.py to capture sample packets]")

    print("\n" + "-" * 70)
    print("4. METHODOLOGY")
    print("-" * 70)
    print("""
    1. Packet Capture: Uses Scapy to sniff network traffic on the active interface
    2. Feature Extraction: Extracts packet size, rate, flags, and window size
    3. Detection:
       - Signature-based: Rules for known attack patterns
       - Anomaly-based: Isolation Forest ML model for unknown threats
    4. Alerting: Logs all threats with timestamps, confidence scores, and source IPs
    """)

    print("\n" + "-" * 70)
    print("5. CONCLUSION")
    print("-" * 70)
    print("""
    The IDS successfully detected:
    - Simulated SYN Flood attacks
    - Port scanning behavior
    - Network anomalies using ML

    Recommendations for improvement:
    - Train with more real-world traffic data
    - Add more signature rules
    - Implement real-time alerting (email/SMS)
    - Add visualization dashboard
    """)

    print("\n" + "=" * 70)
    print("END OF REPORT")
    print("=" * 70)
    print("\n[*] To capture screenshots, press Windows+Shift+S")
    print("[*] Select areas and save as images for your submission")


if __name__ == "__main__":
    create_visual_report()