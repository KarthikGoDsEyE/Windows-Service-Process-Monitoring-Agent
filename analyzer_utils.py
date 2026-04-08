import hashlib
import psutil
import subprocess
import requests
import json
import ctypes
from ctypes import wintypes
from config import VT_API_KEY

# ==============================
# ✅ CACHE
# ==============================
vt_cache = {}

# ==============================
# ✅ TRUSTED PUBLISHERS
# ==============================
TRUSTED_PUBLISHERS = [
    "Microsoft",
    "Google",
    "Brave",
    "Mozilla",
    "Intel",
    "NVIDIA",
    "AMD",
    "Apple"
]

def get_file_company_name(file_path):
    try:
        size = ctypes.windll.version.GetFileVersionInfoSizeW(file_path, None)
        if not size:
            return None

        res = ctypes.create_string_buffer(size)
        ctypes.windll.version.GetFileVersionInfoW(file_path, 0, size, res)

        r = ctypes.c_void_p()
        l = wintypes.UINT()

        # Get language and codepage
        ctypes.windll.version.VerQueryValueW(res, "\\VarFileInfo\\Translation", ctypes.byref(r), ctypes.byref(l))

        if not r.value:
            return None

        lang, codepage = ctypes.cast(r, ctypes.POINTER(ctypes.c_ushort * 2)).contents

        query = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\CompanyName"

        ctypes.windll.version.VerQueryValueW(res, query, ctypes.byref(r), ctypes.byref(l))

        if r.value:
            return ctypes.wstring_at(r.value, l.value)

        return None

    except:
        return None

def is_trusted_publisher(publisher):
    if not publisher or publisher == "N/A":
        return False

    publisher = publisher.lower()

    for trusted in TRUSTED_PUBLISHERS:
        if trusted.lower() in publisher:
            return True

    return False

def detect_system_publisher(path):
    path_lower = path.lower()

    if "windows\\system32" in path_lower:
        return "Microsoft Windows"

    if "program files" in path_lower:
        return "Installed Application"

    return "N/A"

# ==============================
# ✅ SIGNATURE CHECK
# ==============================
def check_signature(file_path):
    try:
        command = [
            "powershell",
            "-Command",
            f"(Get-AuthenticodeSignature '{file_path}').SignerCertificate.Subject"
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=5)

        output = result.stdout.strip()

        if output:
            return "Valid", output.replace("CN=", "")

        return "Unknown", "N/A"

    except:
        return "Error", "N/A"


# ==============================
# ✅ HASH
# ==============================
def get_file_hash(file_path):
    try:
        hasher = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)

        return hasher.hexdigest()

    except:
        return "N/A"


# ==============================
# ✅ NETWORK CONNECTIONS
# ==============================
def get_process_connections(pid):
    connections = []

    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.pid == pid and conn.raddr:
                ip = conn.raddr.ip
                port = conn.raddr.port
                connections.append(f"{ip}:{port}")
    except:
        pass

    return connections


# ==============================
# ✅ IP REPUTATION (AbuseIPDB)
# ==============================
def check_ip_reputation(ip):
    if not ABUSEIPDB_API_KEY:
        return "DISABLED"

    # Ignore local/private IPs (don't waste API calls on these)
    if ip.startswith(("127.", "192.168.", "10.", "172.", "::1", "0.0.0.0")):
        return "SAFE"

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }

        response = requests.get(url, headers=headers, params=querystring, timeout=3)

        if response.status_code == 200:
            data = response.json()
            score = data['data']['abuseConfidenceScore']

            # If confidence score is high, it's a known bad IP
            if score > 50:
                return "MALICIOUS"
            elif score > 10:
                return "SUSPICIOUS"
            else:
                return "SAFE"
        else:
            return "UNKNOWN"

    except:
        return "UNKNOWN"


# ==============================
# ✅ FILE REPUTATION (VirusTotal)
# ==============================
def check_file_reputation(file_hash):
    try:
        if not VT_API_KEY:
           return "DISABLED"
        if file_hash in vt_cache:
            return vt_cache[file_hash]

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}

        response = requests.get(url, headers=headers, timeout=5)

        if response.status_code == 200:
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)

            if malicious >= 10:
                result = "MALICIOUS"
            elif malicious >= 3:
                result = "SUSPICIOUS"
            else:
                result = "CLEAN"
        else:
            result = "UNKNOWN"

        vt_cache[file_hash] = result
        return result

    except:
        return "UNKNOWN"


# ==============================
# ✅ CLASSIFICATION (SMART)
# ==============================
def classify_process(name, path, signature, publisher):

    path_lower = path.lower()

    # System files
    if "windows\\system32" in path_lower:
        return "SAFE"

    # Trusted publisher
    if is_trusted_publisher(publisher):
        return "SAFE"

    # Temp / AppData (unsigned)
    if ("temp" in path_lower or "appdata" in path_lower):
        if signature != "Valid":
            return "HIGH"

    # Downloads EXE (unsigned)
    if "downloads" in path_lower and ".exe" in path_lower:
        if signature != "Valid":
            return "HIGH"

    # Default
    if signature == "Valid":
        return "LOW"

    return "MEDIUM"


# ==============================
# ✅ CACHE SAVE/LOAD
# ==============================
def save_cache():
    with open("vt_cache.json", "w") as f:
        json.dump(vt_cache, f)


def load_cache():
    global vt_cache
    try:
        with open("vt_cache.json", "r") as f:
            vt_cache = json.load(f)
    except:
        vt_cache = {}

def is_online_mode():
    # No API key → offline
    if not VT_API_KEY:
        return False

    try:
        response = requests.get("https://www.google.com", timeout=3)
        return response.status_code == 200
    except:
        return False