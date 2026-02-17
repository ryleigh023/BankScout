import pandas as pd
from pyod.models.iforest import IForest

def detect_anomalies(logs):

    if len(logs) == 0:
        return []

    df = pd.DataFrame(logs)

    # Safe string handling for event_type (SIEM/EDR may have nulls or missing keys)
    event_type = df.get("event_type", pd.Series([""] * len(df)))
    event_str = event_type.fillna("").astype(str).str.lower()

    df["failed_login"] = event_str.str.contains("fail", regex=False).astype(int)
    df["login"] = event_str.str.contains("login", regex=False).astype(int)

    ts = pd.to_datetime(df["timestamp"], errors="coerce")
    df["after_hours"] = (ts.dt.hour < 6) | (ts.dt.hour > 22)
    df["after_hours"] = df["after_hours"].fillna(False).astype(int)

    user_stats = df.groupby("user").agg({
        "failed_login": "sum",
        "login": "sum",
        "after_hours": "sum"
    }).reset_index()

    model = IForest(contamination=0.2)
    model.fit(user_stats[["failed_login", "login", "after_hours"]])

    user_stats["anomaly_score"] = model.decision_scores_
    user_stats["is_anomaly"] = model.labels_

    return user_stats.to_dict(orient="records")
