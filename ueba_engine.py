import pandas as pd
from typing import Dict, List


def compute_ueba_scores(logs: List[dict]) -> Dict[str, float]:
    """
    Compute per-user UEBA (User and Entity Behaviour Analytics) scores.

    This function builds a simple time-series profile of each user's security
    events and uses tsfresh + PyOD to detect behavioural anomalies.

    - tsfresh extracts temporal features per user.
    - IForest scores how far each user's behaviour deviates from the population.

    Returns a mapping of user -> UEBA score in the range [0, 100],
    where higher values indicate more anomalous behaviour.
    """

    if not logs:
        return {}

    df = pd.DataFrame(logs)

    if "user" not in df.columns or "timestamp" not in df.columns:
        # Fallback: cannot compute UEBA without core fields
        return {}

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    if df.empty:
        return {}

    # Map event types to a simple numeric "behaviour weight"
    def event_weight(event: str) -> int:
        event = (event or "").lower()
        if "fail" in event or "denied" in event or "error" in event:
            return 3
        if "privilege" in event or "admin" in event or "policy" in event:
            return 2
        return 1

    event_col = df["event_type"].fillna("").astype(str) if "event_type" in df.columns else pd.Series(["1"] * len(df))
    df["value"] = event_col.apply(lambda e: event_weight(e))
    df["id"] = df["user"]

    # tsfresh expects columns: id, time, value
    ts_df = df[["id", "timestamp", "value"]].rename(columns={"timestamp": "time"})

    try:
        from tsfresh.feature_extraction import extract_features
    except ImportError:
        return {}

    # Extract a compact set of time-series features per user
    try:
        features = extract_features(
            ts_df,
            column_id="id",
            column_sort="time",
            disable_progressbar=True,
        )
    except Exception:
        return {}

    if features.empty or len(features) < 2:
        return {}

    # PyOD/sklearn cannot handle NaN; tsfresh often produces NaN with short series
    features = features.fillna(0.0)
    # Drop any columns that are still non-finite (e.g. inf)
    features = features.replace([float("inf"), float("-inf")], 0.0)

    try:
        from pyod.models.iforest import IForest
        model = IForest(contamination=min(0.2, 0.5 * (1 - 1 / len(features))))
        model.fit(features)
        scores = model.decision_scores_
    except Exception:
        return {}

    max_score = float(scores.max()) if len(scores) else 1.0
    min_score = float(scores.min()) if len(scores) else 0.0

    ueba_scores: Dict[str, float] = {}

    for idx, (user_id, _) in enumerate(features.iterrows()):
        raw = float(scores[idx])
        if max_score == min_score:
            norm = 0.0
        else:
            norm = (raw - min_score) / (max_score - min_score)
        ueba_scores[str(user_id)] = float(norm * 100.0)  # 0–100 scale

    return ueba_scores

