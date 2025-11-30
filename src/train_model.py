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

print(Fore.CYAN + "Training anomaly detection model with RESEARCHED metrics...")

# --- 1. GENERATE SYNTHETIC TRAINING DATA ---
# Based on 2024 benchmarks for Windows 10/11

# CLUSTER A: IDLE / BACKGROUND SERVICES
# "Doing nothing" or background updaters
# Research: svchost, System, idle Discord, Steam background
idle_cpu = np.random.uniform(0, 5, 2000)        # 0% to 5%
idle_mem = np.random.uniform(0, 800, 2000)      # 0MB to 800MB
idle_data = np.column_stack((idle_cpu, idle_mem))

# CLUSTER B: GENERAL PRODUCTIVITY / BROWSING
# "Working" - Chrome with 20 tabs, Word, Coding (VS Code)
# Research: Chrome (2-4GB), VS Code (1GB), Spotify, Discord active
# Note: Chrome spikes CPU but rarely sustains 100% like a miner
general_cpu = np.random.uniform(5, 45, 1000)    # 5% to 45%
general_mem = np.random.uniform(800, 5000, 1000) # 800MB to 5GB
general_data = np.column_stack((general_cpu, general_mem))

# CLUSTER C: GAMING / HEAVY WORKLOAD
# "Playing" - Valorant, Cyberpunk, Compiling Code
# Research: Valorant (30-60% CPU, 4GB RAM), Cyberpunk (80% CPU, 10GB RAM)
# We set the ceiling high to avoid false positives on AAA games
heavy_cpu = np.random.uniform(30, 95, 500)      # 30% to 95%
heavy_mem = np.random.uniform(3000, 16000, 500) # 3GB to 16GB
heavy_data = np.column_stack((heavy_cpu, heavy_mem))

# Combine all "Normal" behaviors
training_data = np.vstack((idle_data, general_data, heavy_data))

print(Fore.GREEN + f"Generated {len(training_data)} points based on Research Profiles:")
print(Fore.CYAN + " 1. Background (0-5% CPU, <800MB RAM)")
print(Fore.CYAN + " 2. Productivity (5-45% CPU, <5GB RAM)")
print(Fore.CYAN + " 3. Gaming/Heavy (30-95% CPU, 3-16GB RAM)")

try:
    # 2. TRAIN MODEL
    # Contamination 0.001: We assume our synthetic definitions are perfect.
    model = IsolationForest(contamination=0.001, random_state=42)
    model.fit(training_data)
    
    # 3. SAVE MODEL
    joblib.dump(model, MODEL_FILENAME)
    print(Fore.GREEN + f"✅ Success! Model saved as '{MODEL_FILENAME}'")
    
except Exception as e:
    print(Fore.RED + f"❌ Error training model: {e}")
    exit(1)

# 4. VERIFICATION TEST (The "Anomaly Gap" Check)
print(Fore.CYAN + "\n--- Research-Based Verification ---")

# Scenario 1: Valorant (Real Data: ~25-40% CPU, 3.5GB RAM)
# Should be Normal (1) because it fits Cluster B/C overlap
print(f"Valorant (35% CPU, 3.5GB Mem): {model.predict([[35, 3500]])[0]}")

# Scenario 2: Chrome 4K Stream (Real Data: ~40% CPU, 2.5GB RAM)
# Should be Normal (1) - Fits Cluster B
print(f"Chrome 4K (40% CPU, 2.5GB Mem): {model.predict([[40, 2500]])[0]}")

# Scenario 3: Video Rendering (Real Data: 90% CPU, 12GB RAM)
# Should be Normal (1) - Fits Cluster C high end
print(f"Rendering (90% CPU, 12GB Mem): {model.predict([[90, 12000]])[0]}")

# Scenario 4: THE ANOMALY - "Crypto Miner"
# Research: Miners pin CPU (90-100%) but use tiny RAM (<100MB) to stay stealthy.
# This data point (95, 50) DOES NOT exist in any of our 3 clusters.
# - Too high CPU for Cluster A/B.
# - Too low RAM for Cluster C.
print(f"Crypto Miner (95% CPU, 50MB Mem): {model.predict([[95, 50]])[0]} (Expected: -1)")

# Scenario 5: "Memory Leak" / DoS Script
# 1% CPU but 10GB RAM. (Cluster A CPU, but Cluster C RAM).
# This mismatch is suspicious.
print(f"Memory Leak (1% CPU, 10GB Mem): {model.predict([[1, 10000]])[0]} (Expected: -1)")