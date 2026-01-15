import joblib
import numpy as np
import re
from datetime import datetime
from typing import Dict, Any, Tuple, List, Set

# --- 1. LOAD ML MODEL ---
try:
    process_model = joblib.load("process_anomaly_model.pkl")
    print("2-Feature Process anomaly model loaded successfully.")
except FileNotFoundError:
    print("ERROR: 'process_anomaly_model.pkl' not found. Run 'train_model.py' first.")
    process_model = None

# --- 2. DEFINE SCORING RULES ---
PATCH_SCORE = 10
FIREWALL_OFF_SCORE = 50
ANTIVIRUS_OFF_SCORE = 50
MALICIOUS_C2_SCORE = 80
PERSISTENCE_SCORE = 40
PROCESS_ANOMALY_SCORE = 80
FIM_CHANGE_SCORE = 60
KNOWN_BAD_ITEM_SCORE = 100
OLD_OS_SCORE = 30

# --- TRUSTED PATHS (FALSE POSITIVE FIX) ---
# Processes running from here are considered safe (System & Installed Apps)
TRUSTED_PATHS = [
    r"c:\windows",
    r"c:\program files\windows defender",
    r"c:\program files (x86)\common files",
    r"c:\program files\tailscale",
    r"c:\program files\teamviewer",
    r"c:\program files\WindowsApps",
    r"c:\program files\Microsoft GameInput"
]

# --- 3. HELPER FUNCTIONS ---
def _is_match(value: str, pattern_list: List[Any]) -> bool:
    val = value.lower()
    for pattern in pattern_list:
        if isinstance(pattern, dict):
            pat_str = pattern.get("name", "") or pattern.get("app", "")
        else:
            pat_str = str(pattern)
        if pat_str and pat_str.lower() in val:
            return True
    return False

def _is_safe_path(path: str) -> bool:
    """Checks if the file path belongs to a trusted system directory."""
    if not path: return False
    p = path.lower()
    for trusted in TRUSTED_PATHS:
        if p.startswith(trusted):
            return True
    return False

# --- 4. SCORING FUNCTIONS ---

def _score_process_anomaly(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    if process_model is None:
        return (0, "")
    
    cmdline = log_columns.get("cmdline", "").lower()
    name = log_columns.get("name", "").lower().strip()
    path = log_columns.get("path", "").lower()

    kernel_processes = ["system", "registry", "secure system", "memory compression"]
    if name in kernel_processes:
        return (0, "")
    
    # 1. PATH WHITELIST (Fix for System False Positives)
    # If process runs from Windows or Program Files, ignore it.
    if _is_safe_path(path):
        return (0, "")
    
    # 2. APP ALLOWLIST (User defined)
    app_allow = kwargs.get("app_allow_list", [])
    if _is_match(name, app_allow):
        return (0, "")
    
    # 3. INFRASTRUCTURE NOISE FILTER
    safe_infrastructure = ["conhost.exe", "osqueryd.exe", "osqueryi.exe", "taskmgr.exe", "wsc_proxy.exe", "avdump.exe", "antivirus"]
    if "osquery_shipper" in cmdline or name in safe_infrastructure:
        return (0, "")

    try:
        # Data Extraction
        raw_cpu = float(log_columns.get("cpu_usage_percent", 0))
        mem = float(log_columns.get("memory_mb", 0))
        
        # CPU Prep (Simple clamping)
        cpu_val = 100.0 if raw_cpu > 100 else raw_cpu

        # 4. ML ANOMALY DETECTION
        # Logic: High CPU (>30%) is suspicious if not whitelisted.
        if cpu_val > 30:
            prediction = process_model.predict([[cpu_val, mem]])[0]
            
            if prediction == -1: # Model flagged it as "Different from Baseline"
                
                # 5. MALWARE CONFIRMATION (The Fix for Detection)
                # We only alert if it matches the "Crypto-Miner" profile:
                # HIGH CPU + LOW RAM.
                # Legitimate heavy apps usually use > 300MB RAM.
                # Your malware test uses < 50MB.
                if mem < 300: 
                    return (PROCESS_ANOMALY_SCORE, f"Malware Behavior Detected (High CPU {cpu_val:.1f}% / Low RAM {mem:.1f}MB): {name}")
            
    except Exception as e:
        return (0, "")
        
    return (0, "")

def _score_programs(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    name = log_columns.get("name", "").lower()
    app_block = kwargs.get("app_block_list", [])
    app_allow = kwargs.get("app_allow_list", [])
    if _is_match(name, app_allow): return (0, "")
    for item in app_block:
        # Handle both dicts (from ES) and simple strings
        if isinstance(item, dict):
            blocked_name = item.get("name", "").lower()
            policy_name = item.get("policy", "General Security Policy") # Default if missing
        else:
            blocked_name = str(item).lower()
            policy_name = "General Security Policy"

        # Check if the blocked keyword is inside the running process name
        if blocked_name and blocked_name in name:
            # RETURN THE SPECIFIC POLICY NAME HERE
            return (KNOWN_BAD_ITEM_SCORE, f"Policy Violation [{policy_name}]: {log_columns.get('name')}")

    return (0, "")

def _score_open_sockets(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    remote_port = log_columns.get("remote_port", 0)
    if str(remote_port) in ["4444", "1337", "6667"]: return (MALICIOUS_C2_SCORE, f"Suspicious C2 Connection (Port {remote_port})")
    return (0, "")

def _score_patches(log_columns, **kwargs): return (0, "") 
def _score_startup_items(log_columns, **kwargs): 
    name = log_columns.get("name", "").lower()
    if name in ["nc.exe", "miner.exe"]: return (PERSISTENCE_SCORE, f"Suspicious Startup Item: {name}")
    return (0, "")
def _score_listening_ports(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Data from Osquery: address, port, protocol, pid
    port = str(log_columns.get("port", ""))
    address = log_columns.get("address", "")
    
    # RISKY PORTS LIST (Common targets for attackers)
    # 21=FTP, 22=SSH, 23=Telnet, 445=SMB(WannaCry), 3389=RDP, 135=RPC
    RISKY_PORTS = ["21", "22", "23", "3389"]
    
    # Logic: If a risky port is listening on "0.0.0.0" (All Interfaces), it's a major risk.
    if address == "0.0.0.0" and port in RISKY_PORTS:
        # Uses your existing MALICIOUS_C2_SCORE (80) or similar high score
        return (MALICIOUS_C2_SCORE, f"High Risk Exposure: Critical Port {port} is Open to Public")

    return (0, "")

def _score_antivirus(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Data from Osquery: name, status, start_mode
    name = log_columns.get("name", "")
    status = str(log_columns.get("status", "")).upper() # e.g., "RUNNING", "STOPPED"
    
    # 1. Check Windows Defender (Antivirus)
    if name == "WinDefend":
        if status != "RUNNING":
            return (ANTIVIRUS_OFF_SCORE, "CRITICAL: Windows Defender Antivirus is DISABLED")
            
    # 2. Check MpsSvc (Windows Firewall)
    if name == "MpsSvc":
        if status != "RUNNING":
            return (FIREWALL_OFF_SCORE, "CRITICAL: Windows Firewall is DISABLED")
            
    return (0, "")

def _score_chrome_extensions(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # 1. Get Agent Data (Incoming)
    installed_id = log_columns.get("identifier", "").lower().strip()
    installed_name = log_columns.get("name", "").lower().strip()
    
    # 2. Get Blocklist (From Threat Intel)
    ext_block = kwargs.get("ext_block_list", [])

    for item in ext_block:
        # Handle the dictionary structure from search (3).json
        if isinstance(item, dict):
            blocked_id = item.get("identifier", "").lower().strip()
            blocked_name = item.get("name", "").lower().strip()
            description = item.get("description", "Security Policy Violation")
        else:
            # Fallback for simple string list
            blocked_id = str(item).lower().strip()
            blocked_name = str(item).lower().strip()
            description = "Blocked Extension"

        # MATCHING LOGIC
        # Priority 1: Check ID (Exact Match - Most Accurate)
        if blocked_id and blocked_id == installed_id:
            return (KNOWN_BAD_ITEM_SCORE, f"Malicious Extension [{description}]: {installed_name} ({installed_id})")
        
        # Priority 2: Check Name (Partial Match - Fallback)
        # e.g. Block "VPN" -> Catch "Free VPN", "Super VPN"
        if blocked_name and blocked_name in installed_name:
             return (KNOWN_BAD_ITEM_SCORE, f"Policy Violation [{description}]: {installed_name}")

    return (0, "")

QUERY_SCORING_MAP = {
    "process_events": _score_process_anomaly,
    "programs": _score_programs,
    "open_sockets": _score_open_sockets,
    "startup_items": _score_startup_items,
    "listening_ports": _score_listening_ports,
    "patches": _score_patches,
    "antivirus_status": _score_antivirus,
    "chrome_extensions": _score_chrome_extensions
}

def score_logs(logs: List[Dict[str, Any]], 
               app_allow_list=None, app_block_list=None,
               ext_allow_list=None, ext_block_list=None) -> Tuple[int, List[Dict[str, Any]]]:
    total_score = 0
    detailed_risks = []
    seen_anomalies = set()

    for log in logs:
        query_name = log.get("query_name", "")
        raw_data = log.get("raw_data", {})
        ts = log.get("timestamp", "") 
        
        if query_name in QUERY_SCORING_MAP:
            score_func = QUERY_SCORING_MAP[query_name]
            score, reason = score_func(raw_data, 
                                     log_timestamp=ts,
                                     app_allow_list=app_allow_list or [], 
                                     app_block_list=app_block_list or [],
                                     ext_allow_list=ext_allow_list or [],
                                     ext_block_list=ext_block_list or [])
            if score > 0:
                risk_key = f"{query_name}:{reason}"
                if risk_key not in seen_anomalies:
                    total_score += score
                    detailed_risks.append({"query": query_name, "score": score, "reason": reason, "data": raw_data})
                    seen_anomalies.add(risk_key)
    return total_score, detailed_risks

def categorize_health(total_risk_score: int) -> str:
    if total_risk_score == 0: return "Healthy"
    elif total_risk_score < 50: return "Needs Attention"
    else: return "At Risk (Flagged)"