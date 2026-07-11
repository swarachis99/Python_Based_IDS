import json
from datetime import datetime
import os


def generate_report():
    """Generate a detailed report from IDS logs"""

    report = {
        'timestamp': datetime.now().isoformat(),
        'total_alerts': 0,
        'threat_types': {},
        'top_attackers': {},
        'alerts': []
    }

    # Check if log file exists
    log_file = "ids_alerts.log"
    if not os.path.exists(log_file):
        print("[!] No log file found. Run the IDS first!")
        return

    # Read and parse log file
    with open(log_file, 'r') as f:
        for line in f:
            try:
                # Extract JSON from log line
                parts = line.split(' - ')
                if len(parts) >= 3:
                    alert_data = json.loads(parts[2])
                    report['alerts'].append(alert_data)
                    report['total_alerts'] += 1

                    # Count threat types
                    threat_type = alert_data.get('threat_type', 'unknown')
                    report['threat_types'][threat_type] = report['threat_types'].get(threat_type, 0) + 1

                    # Count attackers
                    src_ip = alert_data.get('source_ip', 'unknown')
                    report['top_attackers'][src_ip] = report['top_attackers'].get(src_ip, 0) + 1

            except:
                continue

    # Sort attackers by count
    report['top_attackers'] = dict(sorted(
        report['top_attackers'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5])

    return report


def print_report(report):
    """Print the report in a readable format"""
    print("\n" + "=" * 60)
    print("          INTRUSION DETECTION SYSTEM REPORT")
    print("=" * 60)
    print(f"Report Generated: {report['timestamp']}")
    print(f"Total Alerts: {report['total_alerts']}")

    print("\n" + "-" * 60)
    print("THREAT TYPE BREAKDOWN")
    print("-" * 60)
    for threat_type, count in report['threat_types'].items():
        print(f"  {threat_type}: {count}")

    print("\n" + "-" * 60)
    print("TOP ATTACKERS (Source IPs)")
    print("-" * 60)
    for ip, count in report['top_attackers'].items():
        print(f"  {ip}: {count} alerts")

    print("\n" + "-" * 60)
    print("SAMPLE ALERTS (First 5)")
    print("-" * 60)
    for i, alert in enumerate(report['alerts'][:5], 1):
        print(f"\n  Alert {i}:")
        print(f"    Type: {alert.get('threat_type')}")
        print(f"    Source: {alert.get('source_ip')}")
        print(f"    Confidence: {alert.get('confidence')}")

    print("\n" + "=" * 60)
    print("END OF REPORT")
    print("=" * 60)


if __name__ == "__main__":
    report = generate_report()
    if report:
        print_report(report)

        # Save to JSON file
        with open("ids_report.json", 'w') as f:
            json.dump(report, f, indent=2)
        print("\n[*] Report saved to ids_report.json")