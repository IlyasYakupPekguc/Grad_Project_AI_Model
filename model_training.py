import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# 1. Veriyi oku
df = pd.read_json("traffic_log.json", lines=True)

# 2. Özellik çıkarımı
df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
grouped = df.groupby("hour").agg({
    "packet_length": ["sum", "count"],
    "dst_ip": pd.Series.nunique,
    "dst_port": pd.Series.nunique
}).fillna(0)

grouped.columns = ["total_bytes", "packet_count", "unique_dst_ip", "unique_dst_port"]

# 3. Normalize et
scaler = StandardScaler()
X = scaler.fit_transform(grouped)

# 4. Isolation Forest ile eğit
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X)

# 5. Kaydet
joblib.dump(model, "anomaly_model.pkl")
joblib.dump(scaler, "scaler.pkl")
