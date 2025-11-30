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

def _score_process_event(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    proc_name = log_columns.get("name", "unknown").lower()
    cpu_str = log_columns.get("cpu_usage_percent", "0")
    mem_str = log_columns.get("memory_mb", "0")
    
    try:
        cpu = float(cpu_str) if cpu_str else 0.0
        mem = float(mem_str) if mem_str else 0.0
    except ValueError:
        return (0, "")

    # 1. CHECK ALLOW LIST
    allow_list = kwargs.get("allow_list", [])
    for item in allow_list:
        if item.get("app_name", "").lower() == proc_name:
            return (0, "") # Allowed

    # 2. RUN ML ANOMALY DETECTION
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
    "patches": _score_patches,               # UPDATED
    "startup_items": _score_startup_items,   # UPDATED
    "process_events": _score_process_event,
    "processes": _score_process_event,
    "open_sockets": _score_open_sockets,
    "windows_firewall_status": _score_firewall,
    "antivirus_product": _score_antivirus,
    "antivirus_status": _score_antivirus,
    "fim": _score_fim,
    # Map remaining to zero to prevent crashes
    "system_info": _return_zero,
    "os_version": _return_zero,
    "missing_patches": _score_patches,
    "bitlocker_info": _return_zero,
    "listening_ports": _return_zero,
    "chrome_extensions": _return_zero,
    "firefox_addons": _return_zero,
    "programs": _return_zero,
    "windows_event_log": _return_zero,
    "windows_event_log_logons": _return_zero,
    "logged_in_users": _return_zero,
}

def score_logs(logs: List[Dict[str, Any]], allow_list: List[Dict[str, str]] = None) -> Tuple[int, List[Dict[str, Any]]]:
    total_score = 0
    detailed_risks = []
    
    # NEW: Track unique anomalies to prevent scoring the same process 20 times
    # Format: "query_name:reason"
    seen_anomalies = set() 
    
    if allow_list is None:
        allow_list = []

    for log in logs:
        query_name = log.get("query_name", "")
        raw_data = log.get("raw_data", {})
        
        if query_name in QUERY_SCORING_MAP:
            score_func = QUERY_SCORING_MAP[query_name]
            score, reason = score_func(raw_data, allow_list=allow_list)
            
            if score > 0:
                # DEDUPLICATION LOGIC
                # Create a unique key for this risk (e.g., "process_events:ML Anomaly... in 'chrome.exe'")
                # This ensures if Chrome appears 10 times in the logs, we only score it ONCE per batch.
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