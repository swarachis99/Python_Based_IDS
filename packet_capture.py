from scapy.all import sniff, wrpcap
import time


def packet_callback(packet):
    print(packet.summary())


def capture_traffic(duration=30, output_file="captured_traffic.pcap"):
    """Capture network traffic for a specified duration"""
    print(f"[*] Capturing traffic for {duration} seconds...")
    print("[*] Please browse the internet or generate network activity.")

    # Capture packets
    packets = sniff(timeout=duration, prn=packet_callback)

    # Save to file
    wrpcap(output_file, packets)
    print(f"[*] Captured {len(packets)} packets saved to {output_file}")
    return packets


if __name__ == "__main__":
    # Capture for 30 seconds
    packets = capture_traffic(duration=30)