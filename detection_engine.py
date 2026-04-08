from config import WHITELIST, SUSPICIOUS_PARENT_CHILD
from process_monitor import get_parent_name


def detect_parent_child(processes):
    alerts = []

    for proc in processes:
        parent = get_parent_name(proc['ppid'])
        path = proc.get('exe') or "Unknown Path"

        if parent:
            for rule in SUSPICIOUS_PARENT_CHILD:
                if parent.lower() == rule[0] and proc['name'].lower() == rule[1]:
                    alerts.append((
                        "HIGH",
                        "Parent-Child Anomaly",
                        f"{parent} → {proc['name']} ({path})"
                    ))

    return alerts


def detect_unknown(processes):
    alerts = []

    for proc in processes:
        name = proc['name']
        path = proc.get('exe') or "Unknown Path"

        if name not in WHITELIST:
            if "windows" in path.lower() or "program files" in path.lower():
                continue

            alerts.append((
                "MEDIUM",
                "Unknown Process",
                f"{name} → {path}"
            ))

    return alerts


def detect_temp_execution(processes):
    alerts = []

    for proc in processes:
        path = proc.get('exe') or "Unknown Path"

        if "temp" in path.lower():
            alerts.append((
                "HIGH",
                "Temp Execution",
                f"{proc['name']} → {path}"
            ))

    return alerts


def detect_new_process(processes, baseline):
    alerts = []

    for proc in processes:
        if proc['name'] not in baseline:
            path = proc.get('exe') or "Unknown Path"

            alerts.append((
                "HIGH",
                "New Process",
                f"{proc['name']} → {path}"
            ))

    return alerts


def detect_services(services):
    alerts = []

    for s in services:
        path = s.get('path') or "Unknown Path"

        if "temp" in path.lower():
            alerts.append((
                "HIGH",
                "Suspicious Service",
                f"{s['name']} → {path}"
            ))

    return alerts