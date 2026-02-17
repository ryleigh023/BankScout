from typing import Dict, List


def compute_risk(user_records: List[Dict]) -> List[Dict]:
    """
    Attach risk and fidelity scores to each user's aggregated record.

    Risk score:
        - Driven by anomaly score from PyOD, failed logins, and after-hours activity
        - Optionally boosted by UEBA score if present

    Fidelity score:
        - How confident we are that this is a *true* security issue
        - Increases when multiple independent signals fire (failed logins,
          after-hours, UEBA anomaly, PyOD anomaly )
    """

    enriched_records: List[Dict] = []

    for record in user_records:
        failed = int(record.get("failed_login", 0) or 0)
        login = int(record.get("login", 0) or 0)
        after_hours = int(record.get("after_hours", 0) or 0)
        anomaly_score = float(record.get("anomaly_score", 0.0) or 0.0)
        is_anomaly = int(record.get("is_anomaly", 0) or 0)
        ueba_score = float(record.get("ueba_score", 0.0) or 0.0)

        # Base risk from anomaly score (normalised) and UEBA
        base = max(anomaly_score, 0.0)
        behavioural = ueba_score / 2.0  # dampen UEBA contribution slightly

        # Heuristic multipliers for security-relevant behaviours
        failed_component = failed * 6
        after_hours_component = after_hours * 4
        anomaly_flag_component = 12 if is_anomaly else 0

        raw_risk = (
            base
            + behavioural
            + failed_component
            + after_hours_component
            + anomaly_flag_component
        )

        # Clamp to a clean 0–100 scale
        risk_score = max(0.0, min(raw_risk, 100.0))

        # Fidelity measures how many *independent* signals agree
        signal_count = 0
        if failed > 0:
            signal_count += 1
        if after_hours > 0:
            signal_count += 1
        if ueba_score >= 50:
            signal_count += 1
        if is_anomaly:
            signal_count += 1

        # Start with a conservative baseline and grow with each corroborating signal
        fidelity_score = 30.0 + signal_count * 15.0
        fidelity_score = max(0.0, min(fidelity_score, 99.0))

        record["risk_score"] = float(risk_score)
        record["fidelity_score"] = float(fidelity_score)
        record["signals"] = {
            "failed_login": failed,
            "login": login,
            "after_hours": after_hours,
            "ueba_score": ueba_score,
            "is_anomaly": bool(is_anomaly),
        }

        enriched_records.append(record)

    return enriched_records

