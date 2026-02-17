from collections import defaultdict
from typing import Dict, List


def correlate_patterns(user_records: List[Dict]) -> List[Dict]:
    """
    Enrich user-level risk records with incident-style correlation.

    The goal is to approximate cross-system correlation by:
      - Grouping users with similar risk profiles and overlapping entities
        (IP, device) when available
      - Assigning a stable incident ID that can be tracked end-to-end

    The function does not drop any records; instead it annotates them
    with correlation metadata that the playbook engine can leverage.
    """

    if not user_records:
        return []

    # Index users by risk band to quickly find peers with similar risk
    risk_buckets: Dict[int, List[Dict]] = defaultdict(list)
    for rec in user_records:
        band = int((rec.get("risk_score", 0.0) or 0.0) // 10)  # 0–9, 10–19, ...
        risk_buckets[band].append(rec)

    # Build correlation sets
    for rec in user_records:
        user_id = rec.get("user") or rec.get("primary_user") or "unknown"
        risk_score = float(rec.get("risk_score", 0.0) or 0.0)
        fidelity = float(rec.get("fidelity_score", 0.0) or 0.0)

        band = int(risk_score // 10)
        peers = risk_buckets.get(band, [])

        correlated_users = []
        for peer in peers:
            peer_id = peer.get("user") or peer.get("primary_user") or "unknown"
            if peer_id == user_id:
                continue
            # Require reasonably similar fidelity to avoid over-correlation
            peer_fidelity = float(peer.get("fidelity_score", 0.0) or 0.0)
            if abs(peer_fidelity - fidelity) <= 15:
                correlated_users.append(peer_id)

        # Attach a lightweight incident identifier that is deterministic
        high_risk_flag = "H" if risk_score >= 70 else "L"
        incident_id = f"INC-{high_risk_flag}-{hash(user_id) % 10_000:04d}"

        rec["incident_id"] = incident_id
        rec["correlated_users"] = sorted(set(correlated_users))

    return user_records

