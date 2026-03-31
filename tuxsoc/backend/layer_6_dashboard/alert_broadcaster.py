"""
alert_broadcaster.py — Layer 6: Real-Time Alert Broadcasting
=============================================================
Maintains an in-memory alert queue populated by the pipeline.
The SOC API (soc_api.py) reads from this queue to serve the dashboard.

Entry point (called by main_orchestrator at the end of each pipeline run):
    from layer_6_dashboard.alert_broadcaster import broadcast_detections
    broadcast_detections(detections)
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any

logger = logging.getLogger("layer_6.alert_broadcaster")

# ── In-memory alert store ─────────────────────────────────────────────────────
# Capped at 500 most-recent alerts so memory stays bounded
_MAX_ALERTS = 500
_alert_queue: deque[dict] = deque(maxlen=_MAX_ALERTS)
_queue_lock  = Lock()

# Running KPI counters (reset per-session by broadcast_detections)
_kpis: dict[str, Any] = {
    "total_processed":  0,
    "critical_count":   0,
    "high_count":       0,
    "medium_count":     0,
    "low_count":        0,
    "auto_blocked":     0,
    "dora_flagged":     0,
    "cis_violations":   0,
    "last_updated":     None,
}
_kpi_lock = Lock()

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _detection_to_alert(det: dict) -> dict:
    """Convert a BackendDetection dict into a compact dashboard alert dict."""
    l4  = det.get("layer4_cvss") or {}
    raw = det.get("raw_event") or {}
    e2  = det.get("engine_2_threat_intel") or {}
    l5  = det.get("l5_response") or {}

    severity   = (l4.get("severity") or "LOW").upper()
    base_score = l4.get("base_score") or 0.0
    cis_count  = len(l4.get("cis_violations") or e2.get("cis_violations") or [])

    return {
        "incident_id":       det.get("incident_id") or det.get("event_id", "UNKNOWN"),
        "timestamp":         det.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "severity":          severity,
        "base_score":        base_score,
        "log_type":          det.get("log_type", "unknown"),
        "mitre_tactic":      e2.get("mitre_tactic", "Unknown"),
        "mitre_technique":   e2.get("mitre_technique_name") or e2.get("mitre_technique", ""),
        "source_ip":         raw.get("source_ip"),
        "affected_user":     raw.get("affected_user"),
        "affected_host":     raw.get("affected_host"),
        "action":            raw.get("action"),
        "requires_auto_block": l4.get("requires_auto_block", False),
        "dora_compliance":   bool(l4.get("dora_compliance")),
        "cis_violation_count": cis_count,
        "ticket_id":         l5.get("ticket_id"),
        "playbook_path":     l5.get("playbook_path"),
        "ai_intent":         (det.get("ai_analysis") or {}).get("intent"),
        "is_master":         det.get("is_master", False),
    }


def broadcast_detections(detections: list[dict]) -> dict:
    """
    Called by main_orchestrator after a pipeline run completes.

    Converts each detection into a compact alert dict and pushes it onto the
    in-memory queue.  Updates the running KPI counters.

    Returns the updated KPI snapshot so the caller can log it.
    """
    if not detections:
        return get_kpis()

    alerts = [_detection_to_alert(d) for d in detections]

    with _queue_lock:
        _alert_queue.extendleft(reversed(alerts))   # newest first

    # Update KPIs
    with _kpi_lock:
        _kpis["total_processed"] += len(alerts)
        _kpis["last_updated"] = datetime.now(timezone.utc).isoformat()
        for a in alerts:
            sev = a["severity"]
            if sev == "CRITICAL":
                _kpis["critical_count"] += 1
            elif sev == "HIGH":
                _kpis["high_count"] += 1
            elif sev == "MEDIUM":
                _kpis["medium_count"] += 1
            else:
                _kpis["low_count"] += 1
            if a["requires_auto_block"]:
                _kpis["auto_blocked"] += 1
            if a["dora_compliance"]:
                _kpis["dora_flagged"] += 1
            _kpis["cis_violations"] += a["cis_violation_count"]

    logger.info(
        "[L6] Broadcast %d alerts — CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d",
        len(alerts),
        sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        sum(1 for a in alerts if a["severity"] == "HIGH"),
        sum(1 for a in alerts if a["severity"] == "MEDIUM"),
        sum(1 for a in alerts if a["severity"] == "LOW"),
    )
    return get_kpis()


def get_alerts(limit: int = 50, severity_filter: str | None = None) -> list[dict]:
    """
    Return the most-recent alerts from the queue.

    Parameters
    ----------
    limit          : max number of alerts to return (default 50, max 500)
    severity_filter: if set (e.g. "CRITICAL"), only return alerts of that severity
    """
    with _queue_lock:
        alerts = list(_alert_queue)

    if severity_filter:
        alerts = [a for a in alerts if a["severity"] == severity_filter.upper()]

    return alerts[:min(limit, _MAX_ALERTS)]


def get_kpis() -> dict:
    """Return a snapshot copy of the current KPI counters."""
    with _kpi_lock:
        return dict(_kpis)


def get_severity_trend(last_n: int = 100) -> dict[str, int]:
    """Return severity counts for the last N alerts (for trend chart)."""
    with _queue_lock:
        recent = list(_alert_queue)[:last_n]
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in recent:
        sev = a.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
