# 🛡️ Python Real-Time Intrusion Detection System (IDS)

A real-time network Intrusion Detection System built with Python that combines **signature-based detection** and **machine learning anomaly detection** to monitor and flag suspicious network traffic.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Detection Rules](#detection-rules)
- [Output & Reports](#output--reports)
- [Limitations](#limitations)
- [Credits](#credits)

---

## Overview

This IDS monitors live network traffic using [Scapy](https://scapy.net/) for packet capture and analysis. It applies two detection strategies in parallel:

- **Signature-based detection** — matches traffic against known attack patterns (SYN Flood, Port Scan)
- **Anomaly-based detection** — uses an Isolation Forest ML model to flag unusual traffic behavior

All alerts are logged with timestamps, source IPs, threat types, and confidence scores.

---

## Features

- 🔴 Real-time packet capture on any network interface
- 🧠 Machine learning anomaly detection (Isolation Forest)
- 📋 Signature rules for SYN Flood and Port Scan attacks
- 📁 Alert logging to `ids_alerts.log`
- 📊 Report generation (text + JSON)
- 🧪 Simulation test mode (no network required)
- 💾 Traffic capture to `.pcap` file (Wireshark compatible)

---

## Project Structure

```
PythonProject/
│
├── main.py                 # Entry point — starts the live IDS
├── ids_system.py           # Core engine (capture, analysis, detection, alerting)
├── packet_capture.py       # Standalone traffic capture to .pcap file
├── report_generator.py     # Parses logs and generates a summary report
├── visual_report.py        # Formatted lab-style visual report
├── test_ids.py             # Simulation test with synthetic attack packets
│
├── ids_alerts.log          # Generated — alert log file
├── ids_report.json         # Generated — JSON report output
└── captured_traffic.pcap   # Generated — raw packet capture file
```

---

## Requirements

- Python 3.8+
- Windows (tested), Linux/macOS compatible
- **Administrator / root privileges** (required for raw packet capture)

### Python Dependencies

```
scapy
scikit-learn
numpy
```

---

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/your-username/python-ids.git
cd python-ids
```

**2. Create and activate a virtual environment**

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

**3. Install dependencies**

```bash
pip install scapy scikit-learn numpy
```

**4. Windows only — install Npcap**

Scapy requires [Npcap](https://npcap.com/#download) for packet capture on Windows. Download and install it before running.

---

## Usage

### Run the live IDS *(requires admin privileges)*

On Windows, right-click PyCharm or Command Prompt and select **"Run as administrator"**, then:

```bash
python main.py
```

Press `Ctrl+C` to stop.

---

### Run the simulation test *(no admin or network required)*

```bash
python test_ids.py
```

Sends synthetic SYN Flood and Port Scan packets through the detection engine and prints results.

---

### Capture raw traffic to a .pcap file

```bash
python packet_capture.py
```

Captures for 30 seconds and saves to `captured_traffic.pcap`. Open with [Wireshark](https://www.wireshark.org/).

---

### Generate a report after running the IDS

```bash
python report_generator.py
```

Reads `ids_alerts.log` and prints a summary. Also saves `ids_report.json`.

---

### Print the visual lab report

```bash
python visual_report.py
```

---

## How It Works

```
Network Traffic
      │
      ▼
┌─────────────────┐
│  Packet Capture  │  ← Scapy sniffs TCP/IP packets on the active interface
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│  Traffic Analyzer    │  ← Extracts features: packet size, rate, flags, window
└────────┬────────────┘
         │
         ▼
┌──────────────────────────────────────┐
│         Detection Engine              │
│                                      │
│  ┌─────────────────────────────┐     │
│  │  Signature-Based Detection  │     │  ← SYN Flood, Port Scan rules
│  └─────────────────────────────┘     │
│                                      │
│  ┌─────────────────────────────┐     │
│  │  Anomaly-Based Detection    │     │  ← Isolation Forest ML model
│  └─────────────────────────────┘     │
└────────┬─────────────────────────────┘
         │
         ▼
┌─────────────────┐
│   Alert System   │  ← Logs to ids_alerts.log, prints critical alerts
└─────────────────┘
```

---

## Detection Rules

| Attack Type | Detection Method | Trigger Condition |
|---|---|---|
| SYN Flood | Signature | TCP flag = SYN and packet rate > 10/sec |
| Port Scan | Signature | Packet size < 100 bytes and rate > 5/sec |
| Unknown Anomaly | ML (Isolation Forest) | Anomaly score < -0.7 |

---

## Output & Reports

### `ids_alerts.log` — example entry
```
2026-07-11 18:30:00,123 - WARNING - {"timestamp": "2026-07-11T18:30:00", "threat_type": "anomaly", "source_ip": "10.0.0.1", "destination_ip": "192.168.1.2", "confidence": 0.57, "details": {...}}
```

### `ids_report.json` — example structure
```json
{
  "timestamp": "2026-07-11T18:53:28",
  "total_alerts": 12,
  "threat_types": {
    "anomaly": 8,
    "signature": 4
  },
  "top_attackers": {
    "10.0.0.1": 5,
    "192.168.1.100": 3
  }
}
```

---

## Limitations

- Signature rules are basic — a production IDS would use a much larger ruleset
- The anomaly detector is pre-trained on synthetic data; accuracy improves with real traffic data
- Only analyzes TCP/IP packets (UDP, ICMP not covered)
- No real-time dashboard (console and log file only)

---

## Credits

- Built following the [FreeCodeCamp IDS tutorial](https://www.freecodecamp.org/news/build-a-real-time-intrusion-detection-system-with-python/)
- [Scapy](https://scapy.net/) — packet capture and manipulation
- [scikit-learn](https://scikit-learn.org/) — Isolation Forest anomaly detection
- [Npcap](https://npcap.com/) — Windows packet capture driver
