import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

print("Training anomaly detection model for processes...")

# 1. SIMULATED "NORMAL" DATA
# We will train a model to recognize 'normal' process behavior.
# Let's assume normal processes use low CPU and low memory.
# We'll create 5000 examples of normal processes.
np.random.seed(42)
normal_data = np.random.rand(5000, 2)
normal_data[:, 0] = normal_data[:, 0] * 30  # Column 0: CPU usage (0-30%)
normal_data[:, 1] = normal_data[:, 1] * 200 # Column 1: Memory (0-200MB)

# 2. CREATE AND TRAIN THE MODEL
# 'contamination=0.01' means we expect 1% of our data to be anomalies
model = IsolationForest(contamination=0.01, random_state=42)
model.fit(normal_data)

# 3. SAVE THE MODEL TO A FILE
model_filename = 'process_anomaly_model.pkl'
joblib.dump(model, model_filename)

print(f"Model trained and saved as '{model_filename}'")

# 4. TEST THE MODEL (Optional)
# A normal process (10% CPU, 50MB RAM)
test_normal = model.predict([[10, 50]])
print(f"Prediction for (10% CPU, 50MB RAM): {test_normal[0]} (Should be 1)")

# An anomalous process (99% CPU, 1500MB RAM)
test_anomaly = model.predict([[99, 1500]])
print(f"Prediction for (99% CPU, 1500MB RAM): {test_anomaly[0]} (Should be -1)")