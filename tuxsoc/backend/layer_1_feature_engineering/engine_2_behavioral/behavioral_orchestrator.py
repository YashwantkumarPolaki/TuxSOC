"""
behavioral_orchestrator.py — Engine 2: Behavioral Feature Extraction
=====================================================================
Computes user baseline deviation scoring from a normalised record.
Called by feature_orchestrator.run_feature_engineering().
"""
from __future__ import annotations


def extract_behavioral_features(
    record: dict,
    velocity_score: float = 0.0,
    off_hours: bool = False,
) -> dict:
    """
    Returns the behavioral_features block for a single record.

    Fields:
      deviation_score  — composite 0.0–1.0 risk score
      velocity_score   — event rate from this source in the session
      is_internal_src  — True if source IP is RFC1918
      risk_state       — raw RiskState field value (lowercased)
      risk_level       — raw RiskLevel field value (lowercased)
    """
    risk_state = (record.get("RiskState") or "").lower()
    risk_level = (record.get("RiskLevel") or "").lower()
    is_internal = record.get("_l1_is_internal", False)

    deviation_score = round(
        min(1.0,
            velocity_score * 0.4
            + (0.2 if off_hours else 0.0)
            + (0.3 if risk_level in ("high", "medium") else 0.0)
            + (0.1 if risk_state == "atrisk" else 0.0)
        ), 4
    )

    return {
        "deviation_score":  deviation_score,
        "velocity_score":   velocity_score,
        "is_internal_src":  is_internal,
        "risk_state":       risk_state or None,
        "risk_level":       risk_level or None,
    }
