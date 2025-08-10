from datetime import datetime
import csv
import datetime

def log_event(event: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {event}")

def save_scan_report(results: dict, filename="scan_report.csv"):
    """
    Save the scan results dictionary to a CSV file.
    Format: IP,Open Ports (comma-separated)
    """
    with open(filename, "w") as f:
        f.write("IP,Open Ports\n")
        for ip, ports in results.items():
            ports_str = ", ".join(str(p) for p in ports) if ports else "No open ports"
            f.write(f"{ip},{ports_str}\n")

    log_event(f"Scan report saved to {filename}")