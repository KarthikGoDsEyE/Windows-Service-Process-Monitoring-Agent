import os
from datetime import datetime

# Define Log Directory and File
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "process_log.txt")

# Ensure the logs folder exists
os.makedirs(LOG_DIR, exist_ok=True)

def log_event(level, event_type, process_name, pid, details=""):
    """
    Writes a beautifully formatted, standardized log entry.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Pad the severity level so all logs align vertically (e.g., "[INFO]    ", "[HIGH]    ")
    level_padded = f"[{level}]".ljust(10)
    
    # Pad the event type to keep columns straight
    event_padded = f"{event_type}".ljust(18)
    
    # Construct the final log string
    log_entry = f"[{timestamp}] {level_padded} {event_padded} | Process: {process_name} (PID: {pid}) | {details}\n"
    
    # Append to the text file
    with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
        f.write(log_entry)

def log_system(message, level="INFO"):
    """For general system messages like 'Monitoring Started'"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level_padded = f"[{level}]".ljust(10)
    
    log_entry = f"[{timestamp}] {level_padded} SYSTEM             | {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
        f.write(log_entry)