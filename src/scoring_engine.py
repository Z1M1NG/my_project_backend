import joblib
import numpy as np
import re
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
PROCESS_ANOMALY_SCORE = 60  # <--- CRITICAL: Updated to 60 to trigger AI
FIM_CHANGE_SCORE = 60
KNOWN_BAD_ITEM_SCORE = 100
OLD_OS_SCORE = 30

# --- 3. HELPER FUNCTIONS ---
def _is_match(value: str, pattern_list: List[Any]) -> bool:
    """
    Checks if 'value' matches any pattern in 'pattern_list'.
    Robustly handles cases where pattern_list contains dicts (from ES) or strings.
    """
    val = value.lower()
    for pattern in pattern_list:
        # CRITICAL FIX: Handle dictionaries from Elasticsearch
        if isinstance(pattern, dict):
            # Extract 'name' or 'app' key if present
            pat_str = pattern.get("name", "") or pattern.get("app", "")
        else:
            pat_str = str(pattern)
            
        if pat_str and pat_str.lower() in val:
            return True
    return False

# --- 4. SCORING FUNCTIONS ---

def _score_process_anomaly(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    """
    Uses Isolation Forest to detect High CPU / Low RAM anomalies.
    Includes filtering for noise and clamping for raw CPU values.
    """
    if process_model is None:
        return (0, "")
    
    name = log_columns.get("name", "").lower()
    cmdline = log_columns.get("cmdline", "").lower()
    
    # --- NOISE FILTER: Ignore Agent and System Processes ---
    # Prevents self-flagging or flagging Windows services that accumulate high CPU time
    if "osquery_shipper" in cmdline:
        return (0, "")
        
    safe_system_procs = ["svchost.exe", "system", "registry", "smss.exe", "csrss.exe", 
                         "wininit.exe", "services.exe", "lsass.exe", "msmpeng.exe", 
                         "explorer.exe", "taskmgr.exe", "audiodg.exe"]
    if name in safe_system_procs:
        return (0, "")

    try:
        # --- CPU CLAMPING LOGIC ---
        # Windows OSQuery often returns accumulated ticks (e.g., 2000000).
        # We clamp this to 100.0 to match the ML model's 0-100 training range.
        raw_cpu = float(log_columns.get("cpu_usage_percent", 0))
        cpu = 100.0 if raw_cpu > 100 else raw_cpu
        
        mem = float(log_columns.get("memory_mb", 0))
        
        # Predict: [[cpu, mem]]
        prediction = process_model.predict([[cpu, mem]])[0]
        
        if prediction == -1: # Anomaly
            return (PROCESS_ANOMALY_SCORE, f"Anomalous Behavior Detected (CPU: {cpu:.1f}%, Mem: {mem:.1f}MB)")
            
    except Exception as e:
        # Fail safe to 0 if data is malformed
        return (0, "")
        
    return (0, "")

def _score_programs(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    name = log_columns.get("name", "")
    app_block = kwargs.get("app_block_list", [])
    app_allow = kwargs.get("app_allow_list", [])
    
    # 1. Check Allowlist (Explicitly Safe)
    if _is_match(name, app_allow):
        return (0, "")
        
    # 2. Check Blocklist (Explicitly Bad)
    if _is_match(name, app_block):
        return (KNOWN_BAD_ITEM_SCORE, f"Policy Violation: {name}")
        
    return (0, "")

def _score_open_sockets(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    remote_port = log_columns.get("remote_port", 0)
    # Heuristic: Common C2 ports
    if str(remote_port) in ["4444", "1337", "6667"]:
        return (MALICIOUS_C2_SCORE, f"Suspicious C2 Connection (Port {remote_port})")
    return (0, "")

def _score_patches(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Placeholder for patch logic
    return (0, "") 

def _score_startup_items(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    name = log_columns.get("name", "Unknown").lower()
    suspicious_startup = ["nc.exe", "trojan.exe", "miner.exe", "mimikatz.exe"]
    if name in suspicious_startup:
        return (PERSISTENCE_SCORE, f"Suspicious Startup Item: {name}")
    return (0, "")

def _score_listening_ports(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    port = log_columns.get("port", 0)
    # Simple check for risky open ports
    if str(port) in ["23", "21", "3389"]: 
        return (10, f"Risky Open Port: {port}")
    return (0, "")

def _score_antivirus(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    # Logic depends on raw data format, assuming 'state' or similar
    # Placeholder: return 0 for now to avoid noise
    return (0, "")

def _score_chrome_extensions(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    name = log_columns.get("name", "")
    ext_block = kwargs.get("ext_block_list", [])
    if _is_match(name, ext_block):
        return (KNOWN_BAD_ITEM_SCORE, f"Malicious Extension: {name}")
    return (0, "")

# --- 5. MAPPING ---
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

# --- 6. MAIN SCORING LOGIC ---
def score_logs(logs: List[Dict[str, Any]], 
               app_allow_list=None, 
               app_block_list=None,
               ext_allow_list=None,
               ext_block_list=None) -> Tuple[int, List[Dict[str, Any]]]:
    
    total_score = 0
    detailed_risks = []
    seen_anomalies = set() # Dedup within batch

    # Default lists if None
    app_allow = app_allow_list if app_allow_list else []
    app_block = app_block_list if app_block_list else []
    ext_allow = ext_allow_list if ext_allow_list else []
    ext_block = ext_block_list if ext_block_list else []

    for log in logs:
        query_name = log.get("query_name", "")
        raw_data = log.get("raw_data", {})
        
        if query_name in QUERY_SCORING_MAP:
            score_func = QUERY_SCORING_MAP[query_name]
            
            score, reason = score_func(raw_data, 
                                     app_allow_list=app_allow, 
                                     app_block_list=app_block,
                                     ext_allow_list=ext_allow,
                                     ext_block_list=ext_block)
            
            if score > 0:
                risk_key = f"{query_name}:{reason}"
                # Prevent duplicate alerts in the same batch from inflating score artificially
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
    if total_risk_score == 0:
        return "Healthy"
    elif total_risk_score < 50:
        return "Needs Attention"
    else:
        return "At Risk (Flagged)"