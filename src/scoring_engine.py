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
PROCESS_ANOMALY_SCORE = 60
FIM_CHANGE_SCORE = 60
KNOWN_BAD_ITEM_SCORE = 100
OLD_OS_SCORE = 30

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

# --- 4. SCORING FUNCTIONS ---

def _score_process_anomaly(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    """
    Uses Isolation Forest to detect High CPU / Low RAM anomalies.
    Implements RATE-BASED CPU Calculation and respects ALLOWLIST.
    """
    if process_model is None:
        return (0, "")
    
    cmdline = log_columns.get("cmdline", "").lower()
    name = log_columns.get("name", "").lower().strip()
    path = log_columns.get("path", "").lower()
    
    # --- CHECK ALLOWLIST (The User-Defined Fix) ---
    # If the process is in the "Approved Applications" list, skip ML checks.
    app_allow = kwargs.get("app_allow_list", [])
    if _is_match(name, app_allow):
        return (0, "")
    
    # --- NOISE FILTER: Infrastructure Whitelist ---
    # Ignore the agent components and their console hosts.
    # Added "osqueryd" (no exe) just in case name parsing varies.
    safe_infrastructure = ["conhost.exe", "osqueryd.exe", "osqueryi.exe", "osqueryd", "taskmgr.exe"]
    
    if "osquery_shipper" in cmdline or name in safe_infrastructure:
        return (0, "")

    try:
        # Data Extraction
        raw_cpu = float(log_columns.get("cpu_usage_percent", 0))
        mem = float(log_columns.get("memory_mb", 0))
        
        # --- CPU INTENSITY CALCULATION ---
        start_time_epoch = float(log_columns.get("start_time", 0))
        log_iso = kwargs.get("log_timestamp", datetime.now().isoformat())
        
        cpu_val = 0.0
        
        if start_time_epoch > 0:
            try:
                if log_iso.endswith('Z'):
                    log_dt = datetime.fromisoformat(log_iso.replace('Z', '+00:00'))
                else:
                    log_dt = datetime.fromisoformat(log_iso)
                
                log_epoch = log_dt.timestamp()
                duration = log_epoch - start_time_epoch
                
                if duration > 10:
                    # Calculate Rate for processes running > 10s
                    if duration > 300:
                        # Long running process: Normalize accumulated ticks
                        if mem < 1000: # Low ram, likely system background
                             return (0, "")
                    else:
                        # Short running process (< 5 mins). Likely Malware Test.
                        cpu_val = 100.0 if raw_cpu > 100 else raw_cpu
                else:
                    # Brand new process. Clamp.
                    cpu_val = 100.0 if raw_cpu > 100 else raw_cpu
            except:
                cpu_val = 100.0 if raw_cpu > 100 else raw_cpu
        else:
            cpu_val = 100.0 if raw_cpu > 100 else raw_cpu

        # Predict
        prediction = process_model.predict([[cpu_val, mem]])[0]
        
        if prediction == -1: # Anomaly
            return (PROCESS_ANOMALY_SCORE, f"Anomalous Behavior Detected (CPU: {cpu_val:.1f}%, Mem: {mem:.1f}MB)")
            
    except Exception as e:
        return (0, "")
        
    return (0, "")

def _score_programs(log_columns: Dict[str, Any], **kwargs) -> Tuple[int, str]:
    name = log_columns.get("name", "")
    app_block = kwargs.get("app_block_list", [])
    app_allow = kwargs.get("app_allow_list", [])
    if _is_match(name, app_allow): return (0, "")
    if _is_match(name, app_block): return (KNOWN_BAD_ITEM_SCORE, f"Policy Violation: {name}")
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
def _score_listening_ports(log_columns, **kwargs): return (0, "")
def _score_antivirus(log_columns, **kwargs): return (0, "")
def _score_chrome_extensions(log_columns, **kwargs): return (0, "")

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