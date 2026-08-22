import json
import os

from utils import current_timestamp


REPORT_DIR = "reports"
REPORT_FILE = os.path.join(REPORT_DIR, "report.json")

def write_report(target, ip, findings, dns_records=None, os_info=None, alive=None):
    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = f"{target}_{current_timestamp().replace(':','-')}.json"
    report_path = os.path.join(REPORT_DIR, filename)
    ...
    print(f"\n[+] JSON report written to {report_path}")

def write_report(target, ip, findings, dns_records=None, os_info=None, alive=None):

    os.makedirs(REPORT_DIR, exist_ok=True)

    report = {
        "target": target,
        "ip": ip,
        "alive": alive,
        "scan_time": current_timestamp(),
        "dns_records": dns_records or {},
        "os_detection": os_info or [],
        "services": findings,
    }

    with open(REPORT_FILE, "w") as file:
        json.dump(report, file, indent=4)

    print(f"\n[+] JSON report written to {REPORT_FILE}")

