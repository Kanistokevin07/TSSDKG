import pandas as pd
from sklearn.ensemble import IsolationForest

df = pd.read_csv("metrics.csv")

model = IsolationForest(contamination=0.2)
df["anomaly"] = model.fit_predict(df[["invalid_ratio", "total_messages"]])

print(df)