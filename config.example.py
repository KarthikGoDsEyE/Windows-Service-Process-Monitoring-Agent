CHECK_INTERVAL = 3

WHITELIST = [
    "System",
    "System Idle Process",
    "explorer.exe",
    "svchost.exe",
]

SUSPICIOUS_PARENT_CHILD = [
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
]

LOG_FILE = "logs/process_log.txt"
REPORT_FILE = "report.json"

# ADD YOUR API KEYS HERE
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY_HERE"
VT_API_KEY = "YOUR_VIRUSTOTAL_KEY_HERE"