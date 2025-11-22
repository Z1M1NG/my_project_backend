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
PATCH_SCORE = 10         # 10 points per missing patch
FIREWALL_OFF_SCORE = 50
ANTIVIRUS_OFF_SCORE = 50
BITLOCKER_OFF_SCORE = 20
HIGH_RISK_PORT_SCORE = 75
LOGON_FAILURE_SCORE = 5
ADMIN_LOGON_SCORE = 25
FIM_CHANGE_SCORE = 60
OLD_OS_SCORE = 30

# --- THREAT INTELLIGENCE SCORES ---
KNOWN_BAD_ITEM_SCORE = 100  # Critical risk for blocked items (Apps/Extensions)
UNKNOWN_ITEM_SCORE = 30     # Moderate risk for new/unknown items

# --- 3. DEFINE ANOMALY PENALTIES (ML-Based) ---
PROCESS_ANOMALY_SCORE = 100

# --- 4. SCORING FUNCTIONS ---

def _score_system_info(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    """Scores 'system_info' logs. Checks for potential OS issues."""
    # Example: Check for old Windows builds (rough approximation)
    build = log_columns.get("build", "0")
    try:
        if int(build) < 19044: # Older than Windows 10 21H2
             return (OLD_OS_SCORE, f"Outdated OS Build Detected: {build}")
    except ValueError:
        pass
    return (0, "")

def _score_patches(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    patch_id = log_columns.get("hotfix_id", "Unknown")
    return (PATCH_SCORE, f"Missing Patch: {patch_id}")

def _score_firewall(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    if log_columns.get("profile") == "public" and log_columns.get("enable") == "0":
        return (FIREWALL_OFF_SCORE, "Public Firewall is Disabled")
    return (0, "")

def _score_antivirus(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    if log_columns.get("state") != "On":
        return (ANTIVIRUS_OFF_SCORE, f"Antivirus '{log_columns.get('name')}' is off")
    return (0, "")

def _score_bitlocker(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    if log_columns.get("protection_status") != "1":
        return (BITLOCKER_OFF_SCORE, f"BitLocker is OFF on drive {log_columns.get('drive_letter')}")
    return (0, "")

def _score_listening_ports(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    port = log_columns.get("port")
    if port == "3389": return (HIGH_RISK_PORT_SCORE, "High-Risk Port Open: RDP (3389)")
    if port == "22": return (50, "Risky Port Open: SSH (22)")
    return (0, "")

def _score_browser_extensions(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    """Checks extension ID against Allow/Block lists."""
    ext_id = log_columns.get("identifier")
    ext_name = log_columns.get("name", "Unknown")
    
    allow_list = context.get("ext_allow_list", []) if context else []
    block_list = context.get("ext_block_list", []) if context else []

    if ext_id in block_list:
        return (KNOWN_BAD_ITEM_SCORE, f"CRITICAL: Blocked Extension Detected '{ext_name}'")
    if ext_id in allow_list:
        return (0, "") 

    return (UNKNOWN_ITEM_SCORE, f"Unverified Extension: '{ext_name}'")

def _score_installed_apps(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    """Checks installed application name against Allow/Block lists."""
    app_name = log_columns.get("name", "Unknown")
    
    app_allow_list = context.get("app_allow_list", []) if context else []
    app_block_list = context.get("app_block_list", []) if context else []

    # Check Block List (Partial match, e.g. "Torrent" matches "uTorrent")
    for bad_app in app_block_list:
        if bad_app.lower() in app_name.lower():
            return (KNOWN_BAD_ITEM_SCORE, f"CRITICAL: Blocked Application Detected '{app_name}'")

    # Check Allow List
    for good_app in app_allow_list:
        if good_app.lower() in app_name.lower():
            return (0, "")

    return (UNKNOWN_ITEM_SCORE, f"Unverified Application: '{app_name}'")

def _score_process_event(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    if not process_model: return (0, "")
    try:
        # Support varying column names from different OSquery configurations
        cpu = float(log_columns.get("cpu_usage_percent", log_columns.get("cpu_percent", 0)))
        mem = float(log_columns.get("memory_mb", log_columns.get("resident_size", 0)))
        
        # If mem is huge (bytes), convert to MB
        if mem > 100000: mem = mem / 1024 / 1024 

        data_point = np.array([[cpu, mem]])
        prediction = process_model.predict(data_point)
        
        if prediction[0] == -1: 
            process_name = log_columns.get('name', 'UnknownProcess')
            return (PROCESS_ANOMALY_SCORE, f"Anomalous Process: {process_name} (CPU: {cpu}%, Mem: {mem}MB)")
    except Exception as e:
        pass 
    return (0, "")

def _score_windows_event_log(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    event_id = log_columns.get("eventid")
    if event_id == "4625": # Failed Login
        return (LOGON_FAILURE_SCORE, "Failed Logon Attempt Detected")
    return (0, "")

def _score_fim(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    path = log_columns.get("target_path", "Unknown file")
    action = log_columns.get("action", "modified")
    return (FIM_CHANGE_SCORE, f"Critical File {action}: {path}")

def _score_logged_in_users(log_columns: Dict[str, Any], context: Dict = None) -> Tuple[int, str]:
    user = log_columns.get("user", "")
    if "admin" in user.lower() and "administrator" not in user.lower(): # Example rule
         return (ADMIN_LOGON_SCORE, f"Privileged User Logon: {user}")
    return (0, "")

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
    "programs": _score_installed_apps,            # <-- NEW
    "process_events": _score_process_event,
    "processes": _score_process_event,
    "windows_event_log": _score_windows_event_log,
    "windows_event_log_logons": _score_windows_event_log, # Mapped to your osquery.conf name
    "fim": _score_fim,
    "logged_in_users": _score_logged_in_users,
}

def categorize_health(total_risk_score: int) -> str:
    if total_risk_score == 0: return "Healthy"
    if 1 <= total_risk_score <= 99: return "Needs Attention"
    return "At Risk (Flagged)"

def process_log(log: Dict[str, Any], context: Dict[str, Any] = None) -> Tuple[int, str]:
    query_name = log.get("name")
    log_columns = log.get("columns", {})
    
    scoring_function = QUERY_SCORING_MAP.get(query_name)
    
    if scoring_function:
        return scoring_function(log_columns, context)
    
    return (0, "")