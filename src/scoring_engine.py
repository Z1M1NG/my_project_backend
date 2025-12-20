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
    # Returns 0 as these are installed patches, not missing ones.
    return (0, "") 

def _score_startup_items(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    name = log_columns.get("name", "Unknown").lower()
    suspicious_startup = ["nc.exe", "trojan.exe", "miner.exe"]
    if name in suspicious_startup:
         return (PERSISTENCE_SCORE, f"Suspicious Startup Item: {name}")
    return (0, "")

def _score_system_info(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    build_str = log_columns.get("build", "0")
    MIN_SAFE_BUILD = 19044 
    try:
        if "." in build_str:
            parts = build_str.split(".")
            if len(parts) >= 3: current_build = int(parts[2])
            else: current_build = int(parts[-1])
        else:
            current_build = int(build_str)

        if current_build < MIN_SAFE_BUILD:
             return (OLD_OS_SCORE, f"Critical Security Risk: OS Build {current_build} is outdated.")
    except Exception:
        pass
    return (0, "")

def _score_process_event(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    proc_name = log_columns.get("name", "unknown").lower()
    cpu_str = log_columns.get("cpu_usage_percent", "0")
    mem_str = log_columns.get("memory_mb", "0")
    
    try:
        cpu = float(cpu_str) if cpu_str else 0.0
        mem = float(mem_str) if mem_str else 0.0
    except ValueError:
        return (0, "")

    # 1. CHECK APP BLOCK LIST (Strict Match)
    block_list = kwargs.get("app_block_list", [])
    for item in block_list:
        blocked_name = item.get("name", "").lower()
        # Strict matching: matches "steam.exe" or "steam" exactly.
        # Prevents "Host" from matching "StartMenuExperienceHost.exe"
        if blocked_name and (blocked_name == proc_name or blocked_name == proc_name.replace(".exe", "")):
             return (KNOWN_BAD_ITEM_SCORE, f"Blocked Application Detected: '{proc_name}' (Matched: {blocked_name})")

    # 2. CHECK APP ALLOW LIST
    allow_list = kwargs.get("app_allow_list", [])
    for item in allow_list:
        allowed_name = item.get("name", item.get("app_name", "")).lower()
        # Use substring match for allow list to be more permissive, or strict if preferred.
        # Keeping it permissive for allowlist is usually safer for reducing noise.
        if allowed_name and allowed_name in proc_name:
            return (0, "") # Allowed, skip ML

    # 3. RUN ML ANOMALY DETECTION
    if process_model and (cpu > 1 or mem > 10):
        try:
            features = np.array([[cpu, mem]])
            prediction = process_model.predict(features)[0]
            if prediction == -1:
                return (PROCESS_ANOMALY_SCORE, f"ML Anomaly: High Load ({cpu}% CPU, {mem}MB) in '{proc_name}'")
        except Exception as e:
            print(f"ML Error: {e}")
            
    return (0, "")

# --- NEW: Browser Extension Scoring ---
def _score_browser_extensions(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    """
    Checks Chrome Extensions against the Extension Blocklist.
    """
    ext_name = log_columns.get("name", "Unknown").lower()
    ext_id = log_columns.get("identifier", "").lower()
    
    # Fetch Extension Lists from kwargs
    block_list = kwargs.get("ext_block_list", [])
    allow_list = kwargs.get("ext_allow_list", [])

    # 1. Check Allow List (Pass if found)
    for item in allow_list:
        allowed_id = item.get("identifier", "").lower()
        if allowed_id and allowed_id == ext_id:
            return (0, "")

    # 2. Check Block List (Flag if found)
    for item in block_list:
        blocked_id = item.get("identifier", "").lower()
        blocked_name = item.get("name", "").lower()
        
        # Check ID match (Strongest)
        if blocked_id and blocked_id == ext_id:
            return (KNOWN_BAD_ITEM_SCORE, f"Blocked Extension ID Detected: '{ext_name}' ({ext_id})")
        
        # Check Name match (Fallback)
        if blocked_name and blocked_name == ext_name:
            return (KNOWN_BAD_ITEM_SCORE, f"Blocked Extension Name Detected: '{ext_name}'")

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
    app_name = log_columns.get("name", "Unknown").lower()
    block_list = kwargs.get("app_block_list", []) 
    
    for item in block_list:
        blocked_name = item.get("name", "").lower()
        # Strict match for installed apps too
        if blocked_name and blocked_name == app_name.lower():
            return (KNOWN_BAD_ITEM_SCORE, f"Prohibited Software Installed: '{app_name}'")
    return (0, "")

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
    "process_events": _score_process_event,
    "processes": _score_process_event,
    "programs": _score_installed_apps, 
    "chrome_extensions": _score_browser_extensions,
    "firefox_addons": _score_browser_extensions,
    "open_sockets": _score_open_sockets,
    "startup_items": _score_startup_items,   
    "system_info": _score_system_info, 
    "windows_firewall_status": _score_firewall,
    "antivirus_product": _score_antivirus,
    "antivirus_status": _score_antivirus,
    "fim": _score_fim,
    
    # Map remaining to zero
    "os_version": _return_zero,
    "patches": _score_patches,
    "missing_patches": _score_patches,
    "bitlocker_info": _return_zero,
    "listening_ports": _return_zero,
    "windows_event_log": _return_zero,
    "windows_event_log_logons": _return_zero,
    "logged_in_users": _return_zero,
}

# UPDATED: Accepts 4 separate lists
def score_logs(logs: List[Dict[str, Any]], 
               app_allow_list: List[Dict[str, str]] = None, 
               app_block_list: List[Dict[str, str]] = None,
               ext_allow_list: List[Dict[str, str]] = None,
               ext_block_list: List[Dict[str, str]] = None) -> Tuple[int, List[Dict[str, Any]]]:
    
    total_score = 0
    detailed_risks = []
    seen_anomalies = set() 
    
    # Initialize defaults
    app_allow = app_allow_list if app_allow_list else []
    app_block = app_block_list if app_block_list else []
    ext_allow = ext_allow_list if ext_allow_list else []
    ext_block = ext_block_list if ext_block_list else []

    for log in logs:
        query_name = log.get("query_name", "")
        raw_data = log.get("raw_data", {})
        
        if query_name in QUERY_SCORING_MAP:
            score_func = QUERY_SCORING_MAP[query_name]
            
            # Pass ALL lists to the function via kwargs
            score, reason = score_func(raw_data, 
                                     app_allow_list=app_allow, 
                                     app_block_list=app_block,
                                     ext_allow_list=ext_allow,
                                     ext_block_list=ext_block)
            
            if score > 0:
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