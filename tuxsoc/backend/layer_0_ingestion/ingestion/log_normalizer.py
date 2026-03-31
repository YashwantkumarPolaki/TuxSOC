"""
log_normalizer.py — Layer 0: Record Normalisation
==================================================
Accepts a raw log dict in any of the supported formats and returns a
normalised flat dict that Layer 1 feature engineering can consume.

Supported input formats:
  - Azure AD / Office 365 sign-in logs (IpAddress, UserPrincipalName, OperationName)
  - ECS flat schema (source.ip, user.name, event.action)
  - Generic syslog / CEF key-value pairs
  - Raw JSON with arbitrary field names

The normaliser does NOT drop unknown fields — it merges them into the
output so downstream layers can still access them.
"""

from __future__ import annotations

_FIELD_ALIASES: dict[str, list[str]] = {
    "source_ip":      ["IpAddress", "ClientIP", "RemoteAddress", "src_ip",
                       "source_ip", "SourceIP"],
    "destination_ip": ["DestinationIP", "ServerIP", "dest_ip", "destination_ip"],
    "affected_user":  ["UserPrincipalName", "UserId", "AccountName", "user",
                       "username", "affected_user"],
    "action":         ["OperationName", "Operation", "Activity", "action",
                       "event_type", "EventType"],
    "timestamp":      ["TimeGenerated", "@timestamp", "timestamp", "time",
                       "EventTime"],
    "log_type":       ["log_type", "log_family", "LogType"],
    "risk_level":     ["RiskLevel", "risk_level"],
    "risk_state":     ["RiskState", "risk_state"],
}


def _resolve(record: dict, canonical: str) -> str | None:
    """Return the first non-empty value for a canonical field."""
    for alias in _FIELD_ALIASES.get(canonical, [canonical]):
        v = record.get(alias)
        if v is not None and v != "" and v != "null":
            return str(v)
    # Also check nested source / destination / event dicts (ECS)
    if canonical == "source_ip":
        src = record.get("source")
        if isinstance(src, dict):
            return src.get("ip")
    if canonical == "destination_ip":
        dst = record.get("destination")
        if isinstance(dst, dict):
            return dst.get("ip")
    if canonical == "affected_user":
        user = record.get("user")
        if isinstance(user, dict):
            return user.get("name")
    if canonical == "action":
        evt = record.get("event")
        if isinstance(evt, dict):
            return evt.get("action")
    return None


def normalize_record(raw: dict) -> dict:
    """
    Normalise a single raw log record.

    Returns the original record merged with a `raw_event` sub-dict
    containing the canonical field names Layer 1 expects.
    """
    raw_event = {
        "source_ip":      _resolve(raw, "source_ip"),
        "destination_ip": _resolve(raw, "destination_ip"),
        "affected_user":  _resolve(raw, "affected_user"),
        "action":         _resolve(raw, "action"),
        "timestamp":      _resolve(raw, "timestamp"),
    }

    # Merge: original fields + resolved raw_event
    normalised = {
        **raw,
        "raw_event": raw_event,
        # Promote timestamp to top-level for downstream convenience
        "@timestamp": raw_event["timestamp"] or raw.get("@timestamp"),
    }

    return normalised
