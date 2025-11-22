import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

print("Training anomaly detection model for processes...")

# 1. SIMULATED "NORMAL" DATA
# We need to teach the model that BOTH "idle" and "heavy work" are normal.

np.random.seed(42)

# Cluster A: "Idle / Light Tasks" (Browsing, Word, Background services)
# CPU: 0-30%, Memory: 50-500 MB
idle_cpu = np.random.normal(loc=10, scale=10, size=3000)
idle_mem = np.random.normal(loc=200, scale=100, size=3000)

# Cluster B: "Heavy Legitimate Work" (Compiling, Rendering, Gaming)
# CPU: 60-100%, Memory: 1000-4000 MB
heavy_cpu = np.random.normal(loc=80, scale=15, size=1000)
heavy_mem = np.random.normal(loc=2500, scale=800, size=1000)

# Combine them into one "Normal" dataset
cpu_data = np.concatenate([idle_cpu, heavy_cpu])
mem_data = np.concatenate([idle_mem, heavy_mem])

# Clip values to realistic bounds (0-100% CPU, >0 Memory)
cpu_data = np.clip(cpu_data, 0, 100)
mem_data = np.clip(mem_data, 0, 16000) # Max 16GB

# Stack into the format [CPU, Memory]
training_data = np.column_stack((cpu_data, mem_data))

print(f"Training on {len(training_data)} data points (Idle + Heavy Work).")

# 2. CREATE AND TRAIN THE MODEL
# We use 'contamination=0.005' (0.5%) because we are now including heavy work
# as "normal", so true anomalies should be rare.
model = IsolationForest(contamination=0.005, random_state=42)
model.fit(training_data)

# 3. SAVE THE MODEL
model_filename = 'process_anomaly_model.pkl'
joblib.dump(model, model_filename)
print(f"Model trained and saved as '{model_filename}'")

# 4. TEST THE MODEL (Verification)
print("\n--- Testing Predictions ---")

# Normal Idle (Should be 1)
print(f"Idle (10% CPU, 200MB Mem):   {model.predict([[10, 200]])[0]}")

# Normal Heavy Work (Should be 1) <-- This is the fix!
print(f"Heavy Work (90% CPU, 3GB Mem): {model.predict([[90, 3000]])[0]} (Should be 1)")

# Anomaly: Crypto Miner (High CPU, Very Low Memory)
# Miners often use max CPU but very little RAM compared to a real heavy app like Photoshop.
print(f"Miner (99% CPU, 10MB Mem):    {model.predict([[99, 10]])[0]} (Should be -1)")

# Anomaly: Memory Leak (Low CPU, Huge Memory)
print(f"Leak (5% CPU, 10GB Mem):      {model.predict([[5, 10000]])[0]} (Should be -1)")