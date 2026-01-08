import joblib
import numpy as np
import os
from sklearn.ensemble import IsolationForest
from colorama import Fore, init

init(autoreset=True)

# --- CONFIGURATION ---
MODEL_FILENAME = 'process_anomaly_model.pkl'

print(Fore.CYAN + "Training anomaly detection model with CUSTOM CLIENT BASELINE...")

# --- 1. GENERATE SYNTHETIC TRAINING DATA ---
# CLIENT SPECS: 16GB RAM. Idle is 46% (approx 7.3GB). CPU 8-20%.

# CLUSTER A: IDLE / BACKGROUND (Your specific baseline)
# We teach the model that 6GB-9GB RAM usage is NORMAL.
idle_cpu = np.random.uniform(5, 25, 2000)        # 5% to 25% CPU
idle_mem = np.random.uniform(6000, 9000, 2000)   # 6GB to 9GB RAM (Matches your 46% idle)
idle_data = np.column_stack((idle_cpu, idle_mem))

# CLUSTER B: HEAVY WORKLOAD (Gaming/Compiling)
# High CPU + High RAM. This is "Normal Heavy" usage.
heavy_cpu = np.random.uniform(40, 90, 1000)      # 40% to 90% CPU
heavy_mem = np.random.uniform(8000, 15000, 1000) # 8GB to 15GB RAM
heavy_data = np.column_stack((heavy_cpu, heavy_mem))

# Combine datasets (We do NOT include the malware profile here, so it remains an anomaly)
X_train = np.vstack((idle_data, heavy_data))

# --- 2. TRAIN ISOLATION FOREST ---
# Contamination 0.01 means we expect 1% of data to be outliers.
print(Fore.YELLOW + f"Training on {len(X_train)} data points...")
model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
model.fit(X_train)

try:    
    joblib.dump(model, MODEL_FILENAME)
    print(Fore.GREEN + f"✅ Success! Model saved. It now accepts High RAM as normal.")
except Exception as e:
    print(Fore.RED + f"❌ Error saving model: {e}")