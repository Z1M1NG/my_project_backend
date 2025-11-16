import joblib
import numpy as np
from typing import Dict, Any, Tuple

# --- 1. LOAD ML MODEL ---
# --- UPDATED ---
# Load the 2-feature model you created with train_model.py
try:
    process_model = joblib.load("process_anomaly_model.pkl") # <-- FIX 1: Correct filename
    print("2-Feature Process anomaly model loaded successfully.")
except FileNotFoundError:
    print("ERROR: 'process_anomaly_model.pkl' not found. Run 'train_model.py' first.")
    process_model = None

# --- 2. DEFINE SCORING RULES (Rule-Based) ---
# These are the "penalty points" for bad configurations.
# This makes your scoring logic modular and easy to change.
PATCH_SCORE = 10         # 10 points for each missing patch
FIREWALL_OFF_SCORE = 50  # 50 points if firewall is off
ANTIVIRUS_OFF_SCORE = 50 # 50 points if antivirus is off
BITLOCKER_OFF_SCORE = 20 # 20 points if disk is not encrypted

# --- 3. DEFINE ANOMALY PENALTIES (ML-Based) ---
PROCESS_ANOMALY_SCORE = 100 # High penalty for a suspicious process

# --- 4. SCORING FUNCTIONS ("Categorizing Module" Part 1) ---
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

# --- THIS FUNCTION IS NOW UPDATED FOR YOUR 2-FEATURE MODEL ---
def _score_process_event(log_columns: Dict[str, Any]) -> Tuple[int, str]:
    """Scores a process event log using the 2-feature ML model."""
    
    # --- THIS IS THE FIX ---
    if not process_model: # <-- FIX 2: Use the correct variable name
        return (0, "")
    # --- END OF FIX ---

    try:
        # 1. Extract the *two* features our model was trained on
        #    We must match the names in our test.http file: "cpu_usage_percent" and "memory_mb"
        cpu_usage = float(log_columns.get("cpu_usage_percent", 0))
        memory_mb = float(log_columns.get("memory_mb", 0))
        
        # 2. Format data for scikit-learn (a 2D array with 2 features)
        data_point = np.array([[cpu_usage, memory_mb]])
        
        # 3. Make a prediction
        prediction = process_model.predict(data_point) # <-- FIX 3: Use the correct variable name
        
        # 'prediction[0]' will be 1 for normal, -1 for anomaly
        if prediction[0] == -1: 
            process_name = log_columns.get('name', 'UnknownProcess')
            return (PROCESS_ANOMALY_SCORE, f"Anomalous Process Detected: {process_name} (CPU: {cpu_usage}%, Mem: {memory_mb}MB)")
            
    except Exception as e:
        print(f"ML process scoring failed: {e}")
        
    return (0, "")
# --- END OF UPDATED FUNCTION ---


# --- 5. CATEGORIZING AND ROUTING ("Categorizing Module" Part 2) ---
# --- UPDATED ---
# This dictionary maps an OSquery query name to the correct scoring function.
QUERY_SCORING_MAP = {
    "missing_patches": _score_patches,
    "windows_firewall_status": _score_firewall,
    "antivirus_product": _score_antivirus,
    "process_events": _score_process_event, # <-- FIX 4: Listen for "process_events"
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
    Main entry point for the scoring engine.
    It routes a log to the correct scoring function based on its query name.
    """
    query_name = log.get("name")
    log_columns = log.get("columns", {})
    
    scoring_function = QUERY_SCORING_MAP.get(query_name)
    
    if scoring_function:
        return scoring_function(log_columns)
    
    return (0, "")