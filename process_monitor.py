import psutil
import time
import os

SUSPICIOUS_KEYWORDS = ["temp", "appdata", "unknown", "malware"]

def is_suspicious(process_name, exe_path):
    name = (process_name or "").lower()
    path = (exe_path or "").lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in name or keyword in path:
            return True
    return False


def monitor_processes():
    print("\nMonitoring processes... Press Ctrl+C to stop.\n")

    try:
        while True:
            os.system('cls')  # clear screen (Windows)

            print(f"{'PID':<8}{'Name':<25}{'CPU%':<8}{'MEM%':<8}{'Status':<12}{'Path'}")
            print("-" * 100)

            for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'exe']):
                try:
                    pid = process.info['pid']
                    name = process.info['name']
                    cpu = process.info['cpu_percent']
                    mem = process.info['memory_percent']
                    path = process.info['exe']

                    suspicious = is_suspicious(name, path)
                    status = "⚠ Suspicious" if suspicious else "Safe"

                    print(f"{pid:<8}{name[:24]:<25}{cpu:<8}{mem:<8.2f}{status:<12}{path}")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            print("\nRefreshing in 5 seconds...")
            time.sleep(5)

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")