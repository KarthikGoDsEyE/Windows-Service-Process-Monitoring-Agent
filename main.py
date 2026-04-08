import psutil
import time
import msvcrt
import datetime

from rich.console import Console # 
from report_generator import generate_report
from logger import log_system, log_event
from analyzer_utils import (
    check_signature,
    classify_process,
    get_file_hash,
    get_process_connections,
    check_file_reputation,
    is_trusted_publisher,
    get_file_company_name,
    detect_system_publisher,
    is_online_mode,
    load_cache,
    save_cache
)

from dashboard import show_dashboard

process_data = {}
previous_pids = set()
console = Console() 


#  FINAL SUMMARY
def show_final_summary(data, mode):
    print("\n" + "=" * 60)
    print("        FINAL MONITORING SUMMARY")
    print("=" * 60)

    total = len(data)
    safe = sum(1 for d in data if d.get("severity") == "SAFE")
    medium = sum(1 for d in data if d.get("severity") == "MEDIUM")
    high = sum(1 for d in data if d.get("severity") in ["HIGH", "MALICIOUS"])

    print(f"\nMode: {mode}\n")
    print(f"Total Processes Scanned : {total}")
    print(f"SAFE Processes          : {safe}")
    print(f"MEDIUM Suspicious       : {medium}")
    print(f"HIGH Risk Detected      : {high}")

    if high > 0:
        print("\n⚠ HIGH RISK PROCESSES:")
        print("-" * 60)

        for item in data:
            if item.get("severity") in ["HIGH", "MALICIOUS"]:
                print(f"🔴 {item['name']}   PID: {item['pid']}")
                print(f"   Path: {item['path']}\n")

    print("-" * 60)
    
    #  FIX: ACTIVATE THE REPORT GENERATOR HERE
    # Grab only the suspicious/malicious items to put in the final report
    alerts_to_report = [item for item in data if item.get("severity") in ["HIGH", "MALICIOUS", "MEDIUM"]]
    generate_report(alerts_to_report) 
    
    print("Monitoring Stopped Successfully")
    print("=" * 60)

#  PROCESS ANALYSIS
def analyze_process(proc):
    try:
        pid = proc.info['pid']
        name = proc.info['name'] or "unknown"

        try:
            path = proc.exe()
        except:
            path = "Access Denied"

        signature, publisher = check_signature(path)

        company_name = get_file_company_name(path)
        if company_name:
            publisher = company_name

        if publisher == "N/A":
            publisher = detect_system_publisher(path)

        severity = classify_process(name, path, signature, publisher)

        if is_trusted_publisher(publisher):
            severity = "SAFE"

        file_hash = get_file_hash(path)
        vt_rep = check_file_reputation(file_hash)

        if vt_rep == "MALICIOUS":
            severity = "HIGH"
        elif vt_rep == "SUSPICIOUS" and severity != "HIGH":
            severity = "MEDIUM"

        connections = get_process_connections(pid)
        conn_info = ", ".join(connections) if connections else "No Network"

        process_data[pid] = {
            "pid": pid,
            "severity": severity,
            "name": name,
            "path": path,
            "connection": conn_info,
            "publisher": publisher
        }

    except:
        pass


#  MONITOR LOOP
def monitor_processes():
    global previous_pids

    current_pids = set()
    new_pids = set()

    for proc in psutil.process_iter(['pid', 'name']):
        pid = proc.info['pid']
        current_pids.add(pid)

        if pid not in previous_pids:
            new_pids.add(pid)

        analyze_process(proc)

    # remove dead processes
    for pid in list(process_data.keys()):
        if pid not in current_pids:
            del process_data[pid]

    previous_pids = current_pids.copy()
    return new_pids


#  MAIN RUNNER (SEQUENTIAL DASHBOARD)
def run():
    load_cache()
    log_system("Monitoring started", "INFO")
    
    #  INITIALIZATION MESSAGE
    console.print("\n[bold cyan]🚀 Monitoring system is initialized... starting data feed.[/bold cyan]\n")
    time.sleep(2) 

    try:
        #  REMOVED the `with Live(...)` context manager entirely
        while True:
            new_pids = monitor_processes()
            mode = "ONLINE" if is_online_mode() else "OFFLINE"

            data = []
            for pid, info in process_data.items():
                info["is_new"] = pid in new_pids
                data.append(info)

                # WRITE TO LOG FILE FOR NEW PROCESSES
                if info["is_new"]:
                    if info["severity"] in ["HIGH", "MALICIOUS"]:
                        event_type = "THREAT_DETECTED"
                        log_level = "CRITICAL"
                    elif info["severity"] == "MEDIUM":
                        event_type = "SUSPICIOUS_PROC"
                        log_level = "WARNING"
                    else:
                        event_type = "NEW_PROCESS"
                        log_level = "INFO"

                    log_event(
                        level=log_level,
                        event_type=event_type,
                        process_name=info["name"],
                        pid=pid,
                        details=f"Path: {info['path']} | Conn: {info['connection']}"
                    )

            # SMART SORTING: Forces NEW processes to the top
            sorted_data = sorted(
                data,
                key=lambda x: (
                    not x.get("is_new", False), 
                    ["HIGH", "MALICIOUS", "MEDIUM", "LOW", "SAFE"].index(x.get("severity", "SAFE"))
                )
            )

            #  PRINTING SEQUENTIALLY (Allows Scrolling)
            current_time = datetime.datetime.now().strftime("%H:%M:%S")
            console.print(f"\n[bold magenta]--- System Scan Snapshot @ {current_time} ---[/bold magenta]")
            console.print(show_dashboard(sorted_data, mode))

            # EXIT HANDLING (Q) & 2-SECOND DELAY
            # We break the 2-second wait into small chunks so it catches your keystroke immediately
            for _ in range(20): 
                time.sleep(0.1)

                if msvcrt.kbhit():
                    key = msvcrt.getch()

                    if key.lower() == b'q':
                        show_final_summary(sorted_data, mode)
                        save_cache()
                        log_system("Monitoring stopped by user", "INFO")
                        return

    except KeyboardInterrupt:
        show_final_summary(sorted_data, mode)
        save_cache()


if __name__ == "__main__":
    run()