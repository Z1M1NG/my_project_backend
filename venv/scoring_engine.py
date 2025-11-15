import joblib
import numpy as np
from typing import Dict, Any, Tuple

# --- 1. LOAD ML MODEL ---
# Load the pre-trained Isolation Forest model
try:
    cpu_model = joblib.load("cpu_anomaly_model.pkl")
    print("CPU anomaly model loaded successfully.")
except FileNotFoundError:
    print("ERROR: 'cpu_anomaly_model.pkl' not found. Run 'train_model.py' first.")
    cpu_model = None

# --- 2. DEFINE SCORING RULES (Rule-Based) ---
# These are the "penalty points" for bad configurations.
# This makes your scoring logic modular and easy to change.
PATCH_SCORE = 10         # 10 points for each missing patch
FIREWALL_OFF_SCORE = 50  # 50 points if firewall is off
ANTIVIRUS_OFF_SCORE = 50 # 50 points if antivirus is off
BITLOCKER_OFF_SCORE = 20 # 20 points if disk is not encrypted

# --- 3. DEFINE ANOMALY PENALTIES (ML-Based) ---
CPU_ANOMALY_SCORE = 100 # 100 points for a suspicious CPU spike

# --- 4. SCORING FUNCTIONS (Categorizing Module) ---
# Each function scores a *specific* log from OSquery

def _score_patches(log_columns: Dict[str, Any]) -> Tuple[int, str]:
    """Scores a log from a 'missing_patches' query."""
    patch_id = log_columns.get("hotfix_id", "Unknown")
    return (PATCH_SCORE, f"Missing Patch: {patch_id}")

def _score_firewall(log_columns: Dict[str, Any]) -> Tuple[int, str]:
    """Scores a log from the 'windows_firewall_status' query."""
    if log_columns.get("profile") == "public" and log_columns.get("enable") == "0":
        return (FIREWALL_OFF_SCORE, "Public Firewall is Disabled")
    return (0, "")

def _score_antivirus(log_columns: Dict[str, Any]) -> Tuple[int, str]:
    """Scores a log from the 'antivirus_product' query."""
    if log_columns.get("state") != "On":
        return (ANTIVIRUS_OFF_SCORE, f"Antivirus '{log_columns.get('name')}' is off")
    return (0, "")

def _score_system_health(log_columns: Dict[str, Any]) -> Tuple[int, str]:
    """Scores a system health log using the ML model."""
    if not cpu_model:
        return (0, "")

    try:
        # Extract the single feature our model was trained on
        cpu_usage = float(log_columns.get("cpu_usage_percent", 0))
        
        # Format for scikit-learn: a 2D array
        data_point = np.array([[cpu_usage]])
        
        # Make a prediction
        prediction = cpu_model.predict(data_point)
        
        if prediction[0] == -1: # -1 means "anomaly"
            return (CPU_ANOMALY_SCORE, f"Anomalous CPU Usage Detected: {cpu_usage}%")
            
    except Exception as e:
        print(f"ML process scoring failed: {e}")
        
    return (0, "")


# --- 5. CATEGORIZING AND ROUTING ---

# This dictionary is the core of your "Categorizing" module.
# It maps an OSquery query name to the correct scoring function.
QUERY_SCORING_MAP = {
    "missing_patches": _score_patches,           # Example query name
    "windows_firewall_status": _score_firewall,
    "antivirus_product": _score_antivirus,
    "system_health": _score_system_health,       # Example query name
    # Add more query names and functions here
    # "process_events": _score_process_event,
}

def categorize_health(total_risk_score: int) -> str:
    """Converts a numerical score into a human-readable health status."""
    if total_risk_score == 0:
        return "Healthy"
    if 1 <= total_risk_score <= 99:
        return "Needs Attention"
    if total_risk_score >= 100:
        return "At Risk (Flagged)"
    return "Unknown"

def process_log(log: Dict[str, Any]) -> Tuple[int, str]:
    """
    Main "Categorizing" function.
    It routes a log to the correct scoring function based on its query name.
    """
    query_name = log.get("name")
    log_columns = log.get("columns", {})
    
    # Find the correct scoring function from our map
    scoring_function = QUERY_SCORING_MAP.get(query_name)
    
    if scoring_function:
        return scoring_function(log_columns)
    
    # If the log is not in our map (e.g., "system_info"), it has no score
    return (0, "")