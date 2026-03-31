"""
soc_api.py — Layer 6: SOC Dashboard FastAPI Service
====================================================
Exposes the in-memory alert queue and KPI counters built by alert_broadcaster
as REST endpoints consumed by the React dashboard.

Endpoints:
  GET /health                     — liveness probe
  GET /api/v1/dashboard/alerts    — paginated alert list (optional ?severity=)
  GET /api/v1/dashboard/kpis      — running KPI counters
  GET /api/v1/dashboard/trend     — severity counts for trend chart
  POST /api/v1/dashboard/ingest   — push a pre-built detections list directly

Run standalone (port 8006):
    python layer_6_dashboard/soc_api.py
"""

from __future__ import annotations

import logging
import os
import sys

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

# Ensure backend root is on sys.path when run standalone
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from layer_6_dashboard.alert_broadcaster import (
    broadcast_detections,
    get_alerts,
    get_kpis,
    get_severity_trend,
)

logger = logging.getLogger("layer_6.soc_api")

app = FastAPI(
    title="tuxSOC Layer 6: SOC Dashboard API",
    description="Real-time alert feed and KPI service for the React dashboard.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "healthy", "service": "layer_6_dashboard"}


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/api/v1/dashboard/alerts")
def list_alerts(
    limit:    int            = Query(default=50,   ge=1, le=500),
    severity: str | None     = Query(default=None, description="Filter by severity (CRITICAL/HIGH/MEDIUM/LOW)"),
):
    """
    Return the most-recent alerts from the in-memory queue.
    Ordered newest-first.
    """
    alerts = get_alerts(limit=limit, severity_filter=severity)
    return {
        "count":  len(alerts),
        "alerts": alerts,
    }


# ── KPIs ──────────────────────────────────────────────────────────────────────

@app.get("/api/v1/dashboard/kpis")
def dashboard_kpis():
    """Running counters: total processed, severity breakdown, DORA/CIS/auto-block."""
    return get_kpis()


# ── Trend ─────────────────────────────────────────────────────────────────────

@app.get("/api/v1/dashboard/trend")
def severity_trend(last_n: int = Query(default=100, ge=1, le=500)):
    """Severity breakdown for the last N alerts — feeds the trend chart."""
    return get_severity_trend(last_n=last_n)


# ── Direct ingest (called by pipeline or tests) ───────────────────────────────

@app.post("/api/v1/dashboard/ingest")
def ingest_detections(detections: list[dict]):
    """
    Accept a list of BackendDetection dicts (same shape as /ingest_file response)
    and push them into the alert queue.  Used by integration tests and when the
    dashboard service runs as a separate process.
    """
    kpis = broadcast_detections(detections)
    return {"status": "ok", "ingested": len(detections), "kpis": kpis}


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    logger.info("Starting tuxSOC Layer 6 Dashboard API on 0.0.0.0:8006")
    uvicorn.run(app, host="0.0.0.0", port=8006, access_log=True)
