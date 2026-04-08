import json
from config import REPORT_FILE

def generate_report(alerts):
    report = {
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)

    print("\nReport saved as:", REPORT_FILE)