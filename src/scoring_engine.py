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

# --- 2. DEFINE SCORING RULES (Rule-Based) ---
PATCH_SCORE = 10         
FIREWALL_OFF_SCORE = 50
ANTIVIRUS_OFF_SCORE = 50
BITLOCKER_OFF_SCORE = 20
HIGH_RISK_PORT_SCORE = 75
LOGON_FAILURE_SCORE = 5
ADMIN_LOGON_SCORE = 25
FIM_CHANGE_SCORE = 60
OLD_OS_SCORE = 30
MALICIOUS_C2_SCORE = 80      # New Score for suspicious outbound connections
PERSISTENCE_SCORE = 40       # New Score for startup items

# --- THREAT INTELLIGENCE SCORES ---
KNOWN_BAD_ITEM_SCORE = 100  
UNKNOWN_ITEM_SCORE = 30     

# --- 3. DEFINE ANOMALY PENALTIES (ML-Based) ---
# REDUCED from 100 to 40 to prevent False Positives. 
# It is now "Suspicious Behavior", not "Confirmed Virus".
PROCESS_ANOMALY_SCORE = 40  

# --- 4. SCORING FUNCTIONS ---

def _score_system_info(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Placeholder - existing logic presumed
    return (0, "")

def _score_patches(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # If missing patches, add risk
    hotfix = log_columns.get("hotfix_id", "Unknown")
    return (PATCH_SCORE, f"Missing Patch: {hotfix}")

def _score_firewall(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    status = log_columns.get("status", "").lower()
    if status == "stopped":
        return (FIREWALL_OFF_SCORE, "Windows Firewall is Disabled")
    return (0, "")
    
def _score_antivirus(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Basic check for WinDefend status
    status = log_columns.get("status", "").lower()
    if status == "stopped":
        return (ANTIVIRUS_OFF_SCORE, "Antivirus Service Stopped")
    return (0, "")

def _score_bitlocker(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Placeholder for bitlocker check
    return (0, "")

def _score_listening_ports(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Placeholder
    return (0, "")

def _score_browser_extensions(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Placeholder
    return (0, "")

def _score_installed_apps(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Placeholder
    return (0, "")

def _score_windows_event_log(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Placeholder
    return (0, "")

def _score_fim(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    return (FIM_CHANGE_SCORE, "File Modification Detected")

def _score_logged_in_users(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    return (0, "")

def _score_process_event(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    """
    Analyzes process behavior using ML, but respects the Allow List first.
    """
    proc_name = log_columns.get("name", "unknown").lower()
    cpu_str = log_columns.get("cpu_usage_percent", "0")
    mem_str = log_columns.get("memory_mb", "0")
    
    # Handle OSQuery sometimes returning empty strings
    try:
        cpu = float(cpu_str) if cpu_str else 0.0
        mem = float(mem_str) if mem_str else 0.0
    except ValueError:
        return (0, "")

    # 1. CHECK ALLOW LIST (From Elasticsearch)
    # The 'allow_list' is passed via kwargs from main.py
    allow_list = kwargs.get("allow_list", [])
    
    # Check if this process name is in our allowed list
    is_whitelisted = False
    for item in allow_list:
        # Assuming allow_list documents have a field 'app_name' 
        if item.get("app_name", "").lower() == proc_name:
            is_whitelisted = True
            break
            
    if is_whitelisted:
        # If allowed, we IGNORE high resource usage. It's a known safe app.
        return (0, "")

    # 2. RUN ML ANOMALY DETECTION
    # Only run if model exists and process is using significant resources (reduce noise)
    if process_model and (cpu > 1 or mem > 10):
        try:
            features = np.array([[cpu, mem]])
            prediction = process_model.predict(features)[0]
            
            if prediction == -1:
                return (PROCESS_ANOMALY_SCORE, f"ML Anomaly: High Resource Usage ({cpu}% CPU, {mem}MB Mem) in '{proc_name}'")
        except Exception as e:
            print(f"ML Error: {e}")
            
    return (0, "")

# --- NEW: Network Socket Scoring ---
def _score_open_sockets(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    remote_port = log_columns.get("remote_port", "0")
    try:
        r_port = int(remote_port)
    except:
        r_port = 0
        
    # Check for suspicious ports often used by C2 malware
    suspicious_ports = [4444, 6667, 1337, 31337] 
    if r_port in suspicious_ports:
        return (MALICIOUS_C2_SCORE, f"Suspicious Outbound Connection to Port {r_port}")
        
    return (0, "")

# --- NEW: Persistence Scoring ---
def _score_startup_items(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Any new startup item could be a risk, but for now we just flag it lightly
    # In a real system, you'd check this against a 'Startup Allow List'
    name = log_columns.get("name", "Unknown")
    return (PERSISTENCE_SCORE, f"Startup Item Detected: {name}")

# --- 5. ROUTING ---
QUERY_SCORING_MAP = {
    "system_info": _score_system_info,
    "os_version": _score_system_info,
    "missing_patches": _score_patches,
    "patches": _score_patches,
    "windows_firewall_status": _score_firewall,
    "antivirus_product": _score_antivirus,
    "bitlocker_info": _score_bitlocker,
    "listening_ports": _score_listening_ports,
    "chrome_extensions": _score_browser_extensions,
    "firefox_addons": _score_browser_extensions,
    "programs": _score_installed_apps,
    "process_events": _score_process_event,
    "processes": _score_process_event,
    "windows_event_log": _score_windows_event_log,
    "windows_event_log_logons": _score_windows_event_log,
    "fim": _score_fim,
    "logged_in_users": _score_logged_in_users,
    "open_sockets": _score_open_sockets,    # <-- NEW
    "startup_items": _score_startup_items,  # <-- NEW
}

def score_logs(logs: List[Dict[str, Any]], allow_list: List[Dict[str, str]] = None) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Main entry point called by main.py.
    """
    total_score = 0
    detailed_risks = []
    
    if allow_list is None:
        allow_list = []

    for log in logs:
        query_name = log.get("query_name", "")
        raw_data = log.get("raw_data", {})
        
        # Dispatch to the correct function
        if query_name in QUERY_SCORING_MAP:
            score_func = QUERY_SCORING_MAP[query_name]
            # Pass allow_list explicitly to the scoring function via kwargs
            score, reason = score_func(raw_data, allow_list=allow_list)
            
            if score > 0:
                total_score += score
                detailed_risks.append({
                    "query": query_name,
                    "score": score,
                    "reason": reason,
                    "data": raw_data
                })

    return total_score, detailed_risks

def categorize_health(total_risk_score: int) -> str:
    if total_risk_score == 0: return "Healthy"
    if 1 <= total_risk_score < 50: return "Low Risk"
    if 50 <= total_risk_score < 100: return "Warning"
    return "Critical"