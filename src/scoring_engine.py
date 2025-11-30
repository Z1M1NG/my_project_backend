import joblib
import numpy as np
from typing import Dict, Any, Tuple, List

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
PROCESS_ANOMALY_SCORE = 40  
FIM_CHANGE_SCORE = 60
KNOWN_BAD_ITEM_SCORE = 100
OLD_OS_SCORE = 30

# --- 4. SCORING FUNCTIONS ---

def _score_patches(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # FIX: OSQuery 'patches' table lists INSTALLED patches, not missing ones.
    # We should NOT score these as risks.
    return (0, "") 

def _score_startup_items(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # FIX: Only score if we identify it as suspicious.
    # For now, we return 0 to prevent scoring legitimate apps like OneDrive.
    # In a real app, you would check this against a "Bad Startup" list.
    name = log_columns.get("name", "Unknown").lower()
    
    # Simple example of a "Bad List"
    suspicious_startup = ["nc.exe", "trojan.exe", "miner.exe"]
    if name in suspicious_startup:
         return (PERSISTENCE_SCORE, f"Suspicious Startup Item: {name}")
         
    return (0, "")

def _score_system_info(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    """
    Checks if the OS Build number is outdated.
    This is the most accurate way to detect a 'Missing Patch' state
    without a CVE database.
    """
    # 1. Get the Build Number
    # OSQuery usually sends 'build' or 'version'
    build_str = log_columns.get("build", "0")
    
    # 2. Define the Minimum Safe Build (Windows 10 21H2)
    # Any build lower than 19044 means the device is missing CRITICAL patches.
    MIN_SAFE_BUILD = 19044 
    
    try:
        # Extract numbers only (handle formatting like '10.0.19045')
        if "." in build_str:
            # Take the last segment if it looks like a build number
            parts = build_str.split(".")
            # Heuristic: usually the 3rd number is the build in 10.0.19045
            if len(parts) >= 3:
                current_build = int(parts[2])
            else:
                current_build = int(parts[-1])
        else:
            current_build = int(build_str)

        # 3. The Check
        if current_build < MIN_SAFE_BUILD:
             return (OLD_OS_SCORE, f"Critical Security Risk: OS Build {current_build} is outdated. Patches are missing.")

    except Exception:
        # If we can't parse the build, we skip scoring to avoid False Positives
        pass

    return (0, "")

def _score_process_event(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    proc_name = log_columns.get("name", "unknown").lower()
    proc_path = log_columns.get("path", "").lower()
    cpu_str = log_columns.get("cpu_usage_percent", "0")
    mem_str = log_columns.get("memory_mb", "0")
    
    try:
        cpu = float(cpu_str) if cpu_str else 0.0
        mem = float(mem_str) if mem_str else 0.0
    except ValueError:
        return (0, "")

    # 1. CHECK BLOCK LIST (Passed from main.py)
    block_list = kwargs.get("block_list", [])
    for item in block_list:
        # FIX: Matches 'name' key from Elasticsearch blocklist
        blocked_name = item.get("name", "").lower()
        if blocked_name and (blocked_name in proc_name or blocked_name in proc_path):
             return (KNOWN_BAD_ITEM_SCORE, f"Blocked Application Detected: '{proc_name}' (Matched: {blocked_name})")

    # 2. CHECK ALLOW LIST (Passed from main.py)
    allow_list = kwargs.get("allow_list", [])
    for item in allow_list:
        # Matches 'name' or 'app_name' key from Elasticsearch allowlist
        allowed_name = item.get("name", item.get("app_name", "")).lower()
        if allowed_name and allowed_name in proc_name:
            return (0, "") # Allowed, skip ML

    # 3. RUN ML ANOMALY DETECTION
    # Filter out low-resource noise
    if process_model and (cpu > 1 or mem > 10):
        try:
            features = np.array([[cpu, mem]])
            prediction = process_model.predict(features)[0]
            
            if prediction == -1:
                return (PROCESS_ANOMALY_SCORE, f"ML Anomaly: High Load ({cpu}% CPU, {mem}MB) in '{proc_name}'")
        except Exception as e:
            print(f"ML Error: {e}")
            
    return (0, "")

def _score_open_sockets(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    remote_port = log_columns.get("remote_port", "0")
    try:
        r_port = int(remote_port)
    except:
        r_port = 0
        
    suspicious_ports = [4444, 6667, 1337, 31337] 
    if r_port in suspicious_ports:
        return (MALICIOUS_C2_SCORE, f"Suspicious Outbound Connection to Port {r_port}")
    return (0, "")

def _score_installed_apps(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    """
    Checks the static inventory of installed programs against the Block List.
    """
    app_name = log_columns.get("name", "Unknown").lower()
    
    # Fetch Block List (Passed from main.py)
    block_list = kwargs.get("block_list", []) 
    
    for item in block_list:
        blocked_name = item.get("name", "").lower()
        
        # Check for exact match or partial match
        if blocked_name and blocked_name in app_name:
            return (KNOWN_BAD_ITEM_SCORE, f"Prohibited Software Detected: '{app_name}' (Matched: {blocked_name})")
            
    return (0, "")

# Placeholder functions for other queries to ensure they exist and return 0
def _return_zero(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    return (0, "")

def _score_firewall(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    status = log_columns.get("status", "").lower()
    if status == "stopped":
        return (FIREWALL_OFF_SCORE, "Windows Firewall is Disabled")
    return (0, "")

def _score_antivirus(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    status = log_columns.get("status", "").lower()
    if status == "stopped":
        return (ANTIVIRUS_OFF_SCORE, "Antivirus Service Stopped")
    return (0, "")

def _score_fim(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    return (FIM_CHANGE_SCORE, "File Modification Detected")


# --- 5. ROUTING ---
QUERY_SCORING_MAP = {
    "patches": _score_patches,               
    "startup_items": _score_startup_items,   
    "process_events": _score_process_event,
    "processes": _score_process_event,
    "open_sockets": _score_open_sockets,
    "windows_firewall_status": _score_firewall,
    "antivirus_product": _score_antivirus,
    "antivirus_status": _score_antivirus,
    "programs": _score_installed_apps, # Added this mapping
    "fim": _score_fim,
    "system_info": _score_system_info, # Added OS Build Check
    
    # Map remaining to zero to prevent crashes
    "os_version": _return_zero,
    "missing_patches": _score_patches,
    "bitlocker_info": _return_zero,
    "listening_ports": _return_zero,
    "chrome_extensions": _return_zero,
    "firefox_addons": _return_zero,
    "windows_event_log": _return_zero,
    "windows_event_log_logons": _return_zero,
    "logged_in_users": _return_zero,
}

def score_logs(logs: List[Dict[str, Any]], allow_list: List[Dict[str, str]] = None, block_list: List[Dict[str, str]] = None) -> Tuple[int, List[Dict[str, Any]]]:
    total_score = 0
    detailed_risks = []
    
    # Track unique anomalies to prevent scoring the same process 20 times
    seen_anomalies = set() 
    
    if allow_list is None: allow_list = []
    if block_list is None: block_list = [] # Initialize block list

    for log in logs:
        query_name = log.get("query_name", "")
        raw_data = log.get("raw_data", {})
        
        if query_name in QUERY_SCORING_MAP:
            score_func = QUERY_SCORING_MAP[query_name]
            
            # Pass BOTH lists explicitly to the scoring function via kwargs
            score, reason = score_func(raw_data, allow_list=allow_list, block_list=block_list)
            
            if score > 0:
                # DEDUPLICATION LOGIC
                # Create a unique key for this risk
                risk_key = f"{query_name}:{reason}"
                
                if risk_key not in seen_anomalies:
                    total_score += score
                    detailed_risks.append({
                        "query": query_name,
                        "score": score,
                        "reason": reason,
                        "data": raw_data
                    })
                    seen_anomalies.add(risk_key)

    return total_score, detailed_risks

def categorize_health(total_risk_score: int) -> str:
    if total_risk_score == 0: return "Healthy"
    if 1 <= total_risk_score < 50: return "Low Risk"
    if 50 <= total_risk_score < 100: return "Warning"
    return "Critical"