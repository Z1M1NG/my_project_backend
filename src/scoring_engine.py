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
    Uses Isolation Forest to detect anomalies based on CALCULATED CPU RATE.
    This solves the 'Accumulated Ticks' issue by dividing CPU Time by Uptime.
    """
    if process_model is None:
        return (0, "")
    
    name = log_columns.get("name", "").lower()
    cmdline = log_columns.get("cmdline", "").lower()
    
    # Simple self-filter (Agent shouldn't flag itself)
    if "osquery_shipper" in cmdline:
        return (0, "")

    try:
        # 1. Get Metric Data
        raw_cpu_ticks = float(log_columns.get("cpu_usage_percent", 0))
        mem = float(log_columns.get("memory_mb", 0))
        
        # 2. Calculate Process Duration
        # We need the log timestamp (passed via kwargs) and process start_time
        log_timestamp_str = kwargs.get("log_timestamp_iso", "")
        proc_start_epoch = float(log_columns.get("start_time", 0))
        
        calculated_cpu_percent = 0.0
        
        if log_timestamp_str and proc_start_epoch > 0:
            # Parse ISO timestamp (e.g., 2026-01-06T09:00:00Z) to Epoch
            # Assuming log timestamp is UTC
            try:
                # Handle 'Z' or +00:00 manually if needed, or use fromisoformat
                if log_timestamp_str.endswith("Z"):
                    log_dt = datetime.fromisoformat(log_timestamp_str.replace("Z", "+00:00"))
                else:
                    log_dt = datetime.fromisoformat(log_timestamp_str)
                
                log_epoch = log_dt.timestamp()
                
                duration_seconds = log_epoch - proc_start_epoch
                
                if duration_seconds > 0:
                    # HEURISTIC: Convert Windows Ticks (usually Microseconds) to Percentage
                    # Formula: (Ticks / (Duration_Seconds * 1,000,000)) * 100
                    # This normalizes "2 million ticks over 2 seconds" -> 100%
                    # And "2 million ticks over 1 week" -> ~0%
                    
                    # Estimate: If raw_cpu is roughly microseconds
                    usage_ratio = raw_cpu_ticks / (duration_seconds * 1000000.0)
                    calculated_cpu_percent = usage_ratio * 100.0
                    
                    # Safety Cap
                    if calculated_cpu_percent > 100: 
                        calculated_cpu_percent = 100.0
                else:
                    # New process (0 duration), fallback to raw clamping
                    calculated_cpu_percent = 100.0 if raw_cpu_ticks > 100 else raw_cpu_ticks
            except:
                # Fallback if time parsing fails
                calculated_cpu_percent = 100.0 if raw_cpu_ticks > 100 else raw_cpu_ticks
        else:
            # Fallback if start_time missing (Old Agent)
            calculated_cpu_percent = 100.0 if raw_cpu_ticks > 100 else raw_cpu_ticks

        # 3. Predict
        prediction = process_model.predict([[calculated_cpu_percent, mem]])[0]
        
        if prediction == -1:
            return (PROCESS_ANOMALY_SCORE, f"Anomalous Behavior (Calc CPU: {calculated_cpu_percent:.1f}%, Mem: {mem:.1f}MB)")
            
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
    if str(remote_port) in ["4444", "1337", "6667"]:
        return (MALICIOUS_C2_SCORE, f"Suspicious C2 Connection (Port {remote_port})")
    return (0, "")

# Pass-through functions
def _score_patches(log_columns, **kwargs): return (0, "") 
def _score_startup_items(log_columns, **kwargs): 
    name = log_columns.get("name", "").lower()
    if name in ["nc.exe", "miner.exe"]: return (PERSISTENCE_SCORE, f"Suspicious Startup: {name}")
    return (0, "")
def _score_listening_ports(log_columns, **kwargs): return (0, "")
def _score_antivirus(log_columns, **kwargs): return (0, "")
def _score_chrome_extensions(log_columns, **kwargs): return (0, "")

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
    seen_anomalies = set()

    for log in logs:
        query_name = log.get("query_name", "")
        raw_data = log.get("raw_data", {})
        timestamp = log.get("timestamp", "") # Extract ISO timestamp
        
        if query_name in QUERY_SCORING_MAP:
            score_func = QUERY_SCORING_MAP[query_name]
            
            score, reason = score_func(raw_data, 
                                     log_timestamp_iso=timestamp, # Pass timestamp for Rate Calc
                                     app_allow_list=app_allow_list or [], 
                                     app_block_list=app_block_list or [],
                                     ext_allow_list=ext_allow_list or [],
                                     ext_block_list=ext_block_list or [])
            
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
    elif total_risk_score < 50: return "Needs Attention"
    else: return "At Risk (Flagged)"