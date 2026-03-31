"""
feature_orchestrator.py — Layer 1: Feature Engineering
=======================================================
Accepts a single normalised record (from Layer 0) and returns an
"enriched event" dict containing computed feature flags that Layer 2
detection engines consume.

Enriched fields added:
  log_family              — classified log type (auth/web/endpoint/network/iot)
  classification_confidence — 0.0–1.0 confidence in the log_family label
  temporal_features       — time-window based flags
  behavioral_features     — user baseline deviation scoring
  statistical_features    — frequency / spike analysis
  identity_features       — user/account metadata extracted
  feature_warnings        — list of extraction issues
  _l1_entropy             — Shannon entropy of the action string (0.0–8.0)
  _l1_is_internal         — True if source_ip is RFC1918
  _l1_velocity_score      — 0.0–1.0 event velocity indicator
  _l1_off_hours           — True if event timestamp is outside 08:00–18:00 UTC
  _l1_risk_keywords       — list of high-risk keywords found in action/uri fields
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

# ── Per-session velocity tracker (in-memory, keyed by session_id + source_ip) ──
_velocity_store: dict[str, list[str]] = defaultdict(list)

# ── RFC1918 private ranges ────────────────────────────────────────────────────
_RFC1918 = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
)

# ── High-risk keyword patterns ────────────────────────────────────────────────
_RISK_KEYWORDS = [
    r"ransomware", r"mimikatz", r"lsass", r"vssadmin", r"procdump",
    r"powershell.*bypass", r"invoke-expression", r"encodedcommand",
    r"union select", r"1=1", r"exec\(", r"cmd\.exe", r"bash -i",
    r"wget.*http", r"curl.*http", r"nc -e", r"netcat",
    r"new-inboxrule", r"forwardto", r"filedownloaded",
    r"mass_file_modification", r"shadow copy",
]
_RISK_RE = re.compile("|".join(_RISK_KEYWORDS), re.IGNORECASE)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Shannon entropy of a string (bits per character, 0.0–8.0)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    return bool(_RFC1918.match(ip))


def _extract_ip(record: dict) -> str | None:
    """Pull source IP from any of the common field locations."""
    for key in ("source_ip", "src_ip", "IpAddress", "ClientIP", "RemoteAddress"):
        v = record.get(key)
        if v:
            return str(v)
    src = record.get("source") or record.get("raw_event", {}).get("source_ip")
    if isinstance(src, dict):
        return src.get("ip")
    if isinstance(src, str):
        return src
    return None


def _extract_user(record: dict) -> str | None:
    for key in ("UserPrincipalName", "UserId", "user", "username",
                "AccountName", "affected_user"):
        v = record.get(key)
        if v and v not in ("null", "N/A", ""):
            return str(v)
    raw = record.get("raw_event", {})
    if isinstance(raw, dict):
        return raw.get("affected_user")
    return None


def _extract_action(record: dict) -> str:
    for key in ("OperationName", "Operation", "Activity", "action",
                "event_type"):
        v = record.get(key)
        if v:
            return str(v)
    raw = record.get("raw_event", {})
    if isinstance(raw, dict):
        v = raw.get("action")
        if v:
            return str(v)
    return ""


def _extract_timestamp(record: dict) -> datetime | None:
    for key in ("TimeGenerated", "@timestamp", "timestamp", "time"):
        v = record.get(key)
        if v:
            try:
                ts = str(v).replace("Z", "+00:00")
                return datetime.fromisoformat(ts)
            except Exception:
                pass
    return None


def _classify_log_family(record: dict, action: str) -> tuple[str, float]:
    """
    Classify the log into a family based on available fields.
    Returns (family, confidence).
    """
    action_lower = action.lower()

    # Explicit log_type field wins
    lt = record.get("log_type") or record.get("log_family") or ""
    if lt:
        return lt, 0.95

    # Field-presence heuristics
    if record.get("UserPrincipalName") or record.get("RiskState") or record.get("RiskLevel"):
        return "auth", 0.90
    if record.get("request") or "http" in action_lower or "uri" in action_lower:
        return "web", 0.85
    if record.get("process") or "process" in action_lower or "cmd" in action_lower:
        return "endpoint", 0.80
    if record.get("dns") or "dns" in action_lower or record.get("network"):
        return "network", 0.75
    if "mqtt" in action_lower or "iot" in action_lower or record.get("device"):
        return "iot", 0.75

    # Action keyword heuristics
    if any(k in action_lower for k in ("sign-in", "login", "logon", "auth", "mfa", "password")):
        return "auth", 0.70
    if any(k in action_lower for k in ("download", "upload", "sharepoint", "onedrive", "mail")):
        return "auth", 0.65
    if any(k in action_lower for k in ("scan", "port", "beacon", "exfil", "lateral")):
        return "network", 0.65

    return "network", 0.40


def _compute_velocity(session_id: str, source_ip: str | None,
                      ts: datetime | None) -> float:
    """
    Returns a 0.0–1.0 velocity score based on how many events from
    this source_ip have been seen in the current session window.
    """
    if not source_ip:
        return 0.0
    key = f"{session_id}::{source_ip}"
    ts_str = ts.isoformat() if ts else datetime.now(timezone.utc).isoformat()
    _velocity_store[key].append(ts_str)
    count = len(_velocity_store[key])
    # Sigmoid-like: 10 events → ~0.5, 30 events → ~0.9
    return round(min(1.0, count / 30.0), 4)


def _is_off_hours(ts: datetime | None) -> bool:
    if ts is None:
        return False
    hour = ts.astimezone(timezone.utc).hour
    return hour < 8 or hour >= 18


# ── Public entry point ────────────────────────────────────────────────────────

def run_feature_engineering(record: dict, session_id: str = "__default__") -> dict:
    """
    Layer 1 entry point. Accepts a single normalised record and returns
    the same record enriched with feature flags.

    Parameters
    ----------
    record     : normalised dict from Layer 0
    session_id : pipeline session key (used for velocity tracking)

    Returns
    -------
    dict — original record merged with enriched feature fields
    """
    warnings: list[str] = []

    # ── Extract raw observables ───────────────────────────────────────
    source_ip = _extract_ip(record)
    dest_ip   = (record.get("destination_ip") or record.get("dest_ip")
                 or record.get("DestinationIP") or record.get("ServerIP"))
    user      = _extract_user(record)
    action    = _extract_action(record)
    ts        = _extract_timestamp(record)

    if not action:
        warnings.append("action_field_missing")
    if not source_ip and not user:
        warnings.append("no_pivot_fields")

    # ── Log family classification ─────────────────────────────────────
    log_family, conf = _classify_log_family(record, action)

    # ── Temporal features ─────────────────────────────────────────────
    off_hours = _is_off_hours(ts)
    temporal_features: dict[str, Any] = {
        "off_hours":        off_hours,
        "timestamp_parsed": ts.isoformat() if ts else None,
        "hour_of_day":      ts.astimezone(timezone.utc).hour if ts else None,
    }

    # ── Behavioral features ───────────────────────────────────────────
    velocity = _compute_velocity(session_id, source_ip, ts)
    is_internal = _is_internal(source_ip)
    risk_state  = (record.get("RiskState") or "").lower()
    risk_level  = (record.get("RiskLevel") or "").lower()

    # Deviation score: combines velocity, off-hours, risk signals
    deviation_score = round(
        min(1.0,
            velocity * 0.4
            + (0.2 if off_hours else 0.0)
            + (0.3 if risk_level in ("high", "medium") else 0.0)
            + (0.1 if risk_state == "atrisk" else 0.0)
        ), 4
    )

    behavioral_features: dict[str, Any] = {
        "deviation_score":  deviation_score,
        "velocity_score":   velocity,
        "is_internal_src":  is_internal,
        "risk_state":       risk_state or None,
        "risk_level":       risk_level or None,
    }

    # ── Statistical features ──────────────────────────────────────────
    entropy = round(_shannon_entropy(action), 4)
    risk_keywords = _RISK_RE.findall(action)

    statistical_features: dict[str, Any] = {
        "action_entropy":   entropy,
        "risk_keyword_hits": len(risk_keywords),
        "risk_keywords":    list(set(k.lower() for k in risk_keywords)),
    }

    # ── Identity features ─────────────────────────────────────────────
    identity_features: dict[str, Any] | None = None
    if user:
        identity_features = {
            "user":          user,
            "risk_level":    risk_level or None,
            "risk_state":    risk_state or None,
            "client_app":    record.get("ClientAppUsed"),
            "location":      record.get("Location"),
            "risk_events":   record.get("RiskEventTypes"),
        }

    # ── Assemble enriched record ──────────────────────────────────────
    enriched = {
        **record,
        # Layer 1 classification
        "log_family":               log_family,
        "classification_confidence": conf,
        # Feature blocks (consumed by Layer 2 engines)
        "temporal_features":        temporal_features,
        "behavioral_features":      behavioral_features,
        "statistical_features":     statistical_features,
        "identity_features":        identity_features,
        "feature_warnings":         warnings,
        # Flat convenience fields (used by _layer2_detect fallback + _shape_detection)
        "_l1_entropy":              entropy,
        "_l1_is_internal":          is_internal,
        "_l1_velocity_score":       velocity,
        "_l1_off_hours":            off_hours,
        "_l1_risk_keywords":        list(set(k.lower() for k in risk_keywords)),
        # Preserve extracted observables for Layer 2
        "_l1_source_ip":            source_ip,
        "_l1_dest_ip":              dest_ip,
        "_l1_user":                 user,
        "_l1_action":               action,
        "_l1_timestamp":            ts.isoformat() if ts else None,
    }

    return enriched
