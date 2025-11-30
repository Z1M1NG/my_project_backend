import joblib
import numpy as np
import pandas as pd
import os
from sklearn.ensemble import IsolationForest
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# --- CONFIGURATION ---
MODEL_FILENAME = 'process_anomaly_model.pkl'
# Ensure you generate a NEW log file with the updated osquery_shipper.py before training!
REAL_DATA_FILE = r"E:\schoolwork\Yr3\Sem_2\FYP\my_project_backend\src\RealLife_logs.csv" 

print(Fore.CYAN + "Training anomaly detection model for processes...")

# 1. LOAD REAL DATA
if os.path.exists(REAL_DATA_FILE):
    print(Fore.GREEN + f"Loading REAL data from {REAL_DATA_FILE}...")
    
    try:
        # Read the CSV
        df = pd.read_csv(REAL_DATA_FILE)
        
        # --- CRITICAL CHANGE: DATA PREPROCESSING ---
        # The updated osquery_shipper.py sends:
        # 'raw_data.cpu_usage_percent' (0-100 scale)
        # 'raw_data.memory_mb' (Size in MB)
        
        # 1. Define column names (Flattened JSON often uses dot notation)
        cpu_col = 'raw_data.cpu_usage_percent'
        mem_col = 'raw_data.memory_mb'

        # 2. Check if columns exist
        if cpu_col not in df.columns or mem_col not in df.columns:
            print(Fore.RED + f"❌ Error: Columns '{cpu_col}' or '{mem_col}' not found in CSV.")
            print("Available columns:", df.columns)
            exit(1)

        # 3. Clean Data: Convert to numeric, turn errors (text/empty) into 0
        df['cpu'] = pd.to_numeric(df[cpu_col], errors='coerce').fillna(0)
        df['mem'] = pd.to_numeric(df[mem_col], errors='coerce').fillna(0)
        
        # 4. Create the training dataset (2 features: CPU, Memory)
        training_data = df[['cpu', 'mem']].values
        
        print(Fore.CYAN + f"Training on {len(training_data)} real data points.")
        print(f"Sample data head:\n{training_data[:5]}")
        
        # 2. TRAIN MODEL
        # contamination=0.01: We assume 1% of your TRAINING logs might be outliers.
        # Ensure your training logs include Gaming/Heavy usage so they aren't marked as outliers!
        model = IsolationForest(contamination=0.01, random_state=42)
        model.fit(training_data)
        
        # 3. SAVE MODEL
        joblib.dump(model, MODEL_FILENAME)
        print(Fore.GREEN + f"✅ Success! Model trained on real data and saved as '{MODEL_FILENAME}'")
        
    except Exception as e:
        print(Fore.RED + f"❌ Error processing CSV file: {e}")
        exit(1)

else:
    print(Fore.YELLOW + f"⚠️ Warning: '{REAL_DATA_FILE}' not found.")
    exit(1)

# 4. VERIFICATION TEST
print(Fore.CYAN + "\n--- Testing Model with Sample Data ---")

# Test 1: IDLE (Should be Normal/1)
test_idle = [[0, 25]] 
pred_idle = model.predict(test_idle)[0]
print(f"Idle Process (0 CPU, 25MB Mem): {pred_idle} (Expected: 1)")

# Test 2: GAMING (Should be Normal/1 IF you trained on gaming data)
test_gaming = [[40, 2500]] 
pred_gaming = model.predict(test_gaming)[0]
print(f"Gaming Process (40 CPU, 2.5GB Mem): {pred_gaming} (Should be 1 if trained properly)")

# Test 3: IMPOSSIBLE ANOMALY (Should be Anomaly/-1)
test_anomaly = [[1000, 4000]] 
pred_anomaly = model.predict(test_anomaly)[0]
print(f"Anomaly (1000 CPU, 4GB Mem): {pred_anomaly} (Expected: -1)")