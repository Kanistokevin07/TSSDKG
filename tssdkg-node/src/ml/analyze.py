import pandas as pd
from sklearn.ensemble import IsolationForest
import os

output_path = os.path.join(os.getcwd(), "src/ml/ml_output.json")


# Load updated CSV
df = pd.read_csv("metrics.csv")

# Select numeric columns relevant for anomaly detection
features = ["invalid_ratio", "validity_rate", "total_messages", "replay_count", "epochs_participated"]

# Fit Isolation Forest
model = IsolationForest(contamination=0.2, random_state=42)
df["anomaly"] = model.fit_predict(df[features])


df["anomaly"] = df["anomaly"].map({1: 0, -1: 1})  # optional: 1 = anomaly, 0 = normal

# Print results


# Optionally save results
df.to_csv("metrics_analyzed.csv", index=False)
df[['node_id', 'anomaly']].to_json(output_path, orient="records")