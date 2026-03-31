"""
temporal_orchestrator.py — Engine 1: Temporal Feature Extraction
=================================================================
Extracts time-window based features from a normalised record.
Called by feature_orchestrator.run_feature_engineering().
"""
from __future__ import annotations
from datetime import datetime, timezone


def extract_temporal_features(record: dict, ts: datetime | None = None) -> dict:
    """
    Returns the temporal_features block for a single record.

    Fields:
      off_hours        — True if event is outside 08:00–18:00 UTC
      timestamp_parsed — ISO8601 string of the parsed timestamp
      hour_of_day      — UTC hour (0–23)
    """
    if ts is None:
        for key in ("TimeGenerated", "@timestamp", "timestamp", "_l1_timestamp"):
            v = record.get(key)
            if v:
                try:
                    ts = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                    break
                except Exception:
                    pass

    if ts is None:
        return {"off_hours": False, "timestamp_parsed": None, "hour_of_day": None}

    utc_ts = ts.astimezone(timezone.utc)
    hour = utc_ts.hour
    return {
        "off_hours":        hour < 8 or hour >= 18,
        "timestamp_parsed": utc_ts.isoformat(),
        "hour_of_day":      hour,
    }
