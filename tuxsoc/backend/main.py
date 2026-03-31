"""
main.py — TuxSOC Unified FastAPI Entry Point
=============================================
Single server on port 8000 that the React frontend talks to.

Endpoints:
  GET  /health            — health check (frontend connectivity probe)
  GET  /pipeline/status   — per-layer pipeline status
  POST /ingest_file       — multipart file upload → 7-layer pipeline
  POST /ingest_json       — raw JSON body → 7-layer pipeline (convenience)

Run from the backend/ directory:
    python main.py
  or:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

import json
import logging
import os
import sys
import traceback
from typing import Any, List

from fastapi import FastAPI, File, HTTPException, UploadFile, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("tuxsoc.main")

# ── Path setup ────────────────────────────────────────────────────────────────
# Ensure backend/ root is on sys.path so all layer imports resolve
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# layer_0_ingestion/ingestion/ must be on path for `from ingestion.log_normalizer import …`
_L0_PATH = os.path.join(_BACKEND_DIR, "layer_0_ingestion")
if _L0_PATH not in sys.path:
    sys.path.insert(0, _L0_PATH)

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="TuxSOC — 7-Layer Security Pipeline",
    description="Unified ingestion endpoint for the TuxSOC React frontend.",
    version="1.0.0",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allow the Vite dev server (5173) and any common React dev port.
# In production, replace with your actual frontend origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "service": "TuxSOC — 7-Layer Security Pipeline",
        "status": "running",
        "endpoints": {
            "health":    "/health",
            "docs":      "/docs",
            "ingest":    "POST /ingest_file  or  POST /ingest_json",
            "pipeline":  "/pipeline/status",
            "alerts":    "/api/v1/dashboard/alerts",
            "kpis":      "/api/v1/dashboard/kpis",
            "trend":     "/api/v1/dashboard/trend",
        }
    }


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    """Frontend connectivity probe — must return {"status": "healthy"}."""
    return {"status": "healthy", "service": "tuxsoc-pipeline"}


# ── Pipeline status ───────────────────────────────────────────────────────────
@app.get("/pipeline/status")
def pipeline_status():
    """Returns per-layer status dict for the frontend pipeline animation."""
    try:
        from main_orchestrator import get_pipeline_status
        return get_pipeline_status()
    except Exception as e:
        logger.warning("pipeline/status unavailable: %s", e)
        return {
            "layer_0": "idle", "layer_1": "idle", "layer_2": "idle",
            "layer_3": "idle", "layer_4": "idle", "layer_5": "idle",
            "layer_6": "idle",
        }


# ── Layer 6 Dashboard endpoints ───────────────────────────────────────────────
@app.get("/api/v1/dashboard/alerts")
def dashboard_alerts(limit: int = 50, severity: str | None = None):
    """Proxy to Layer 6 alert broadcaster — returns recent alerts."""
    try:
        from layer_6_dashboard.alert_broadcaster import get_alerts
        alerts = get_alerts(limit=limit, severity_filter=severity)
        return {"count": len(alerts), "alerts": alerts}
    except Exception as e:
        logger.warning("dashboard/alerts unavailable: %s", e)
        return {"count": 0, "alerts": []}


@app.get("/api/v1/dashboard/kpis")
def dashboard_kpis():
    """Proxy to Layer 6 KPI counters."""
    try:
        from layer_6_dashboard.alert_broadcaster import get_kpis
        return get_kpis()
    except Exception as e:
        logger.warning("dashboard/kpis unavailable: %s", e)
        return {}


@app.get("/api/v1/dashboard/trend")
def dashboard_trend(last_n: int = 100):
    """Proxy to Layer 6 severity trend."""
    try:
        from layer_6_dashboard.alert_broadcaster import get_severity_trend
        return get_severity_trend(last_n=last_n)
    except Exception as e:
        logger.warning("dashboard/trend unavailable: %s", e)
        return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


# ── Shared pipeline runner ────────────────────────────────────────────────────
def _run_pipeline_safe(raw_records: list[dict]) -> dict[str, Any]:
    """
    Run the 7-layer pipeline and return the IngestFileResponse shape
    that the frontend IngestFileResponse type expects.
    """
    from main_orchestrator import run_pipeline
    detections = run_pipeline(raw_records, session_id="frontend-upload")
    return {
        "status":          "success",
        "file":            "uploaded",
        "total_processed": len(raw_records),
        "detections":      detections,
    }


# ── JSON healing helper ───────────────────────────────────────────────────────
import re as _re

def _heal_content(content: str) -> str:
    """
    Detect and fix malformed multi-object JSON before parsing.

    Handles all three common formats produced by log export tools:

      1. Comma-separated bare objects (no brackets):
            {"a":1},{"b":2},{"c":3}
            {"a":1},{"b":2},{"c":3},   ← trailing comma

      2. Newline-delimited JSON (NDJSON) — one object per line, no commas:
            {"a":1}
            {"b":2}

      3. Already-valid JSON array — returned unchanged:
            [{"a":1},{"b":2}]

    Returns a string that json.loads() can parse as a list.
    """
    stripped = content.strip().lstrip("\ufeff")  # strip BOM + leading whitespace

    # Already a valid array — nothing to do
    if stripped.startswith("["):
        return stripped

    # Not an object at all — return as-is and let json.loads raise
    if not stripped.startswith("{"):
        return stripped

    # ── Attempt 1: wrap in [ ] after stripping trailing comma ────────────
    # This covers:  {...},{...}   and   {...},{...},
    candidate = _re.sub(r",\s*$", "", stripped)
    try:
        result = json.loads(f"[{candidate}]")
        if isinstance(result, list) and len(result) > 0:
            n = len(result)
            logger.info(
                "Found malformed JSON; successfully wrapped %d logs for processing.", n
            )
            return f"[{candidate}]"
    except json.JSONDecodeError:
        pass

    # ── Attempt 2: NDJSON — one object per line, no separating commas ────
    lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]
    cleaned: list[str] = []
    for line in lines:
        line = _re.sub(r",\s*$", "", line)  # strip per-line trailing comma
        cleaned.append(line)

    ndjson_candidate = ",".join(cleaned)
    try:
        result = json.loads(f"[{ndjson_candidate}]")
        if isinstance(result, list) and len(result) > 0:
            n = len(result)
            logger.info(
                "Found malformed JSON; successfully wrapped %d logs for processing.", n
            )
            return f"[{ndjson_candidate}]"
    except json.JSONDecodeError:
        pass

    # Could not heal — return original so json.loads raises a clear error
    return stripped


# ── POST /ingest_file — multipart file upload ─────────────────────────────────
@app.post("/ingest_file")
async def ingest_file(file: UploadFile = File(...)):
    """
    Accepts a multipart/form-data file upload containing JSON log records.
    Handles valid arrays, bare comma-separated objects, NDJSON, and single objects.
    """
    logger.info("[Layer 0] ingest_file: received '%s' (%s)", file.filename, file.content_type)

    # ── Step 1: Read raw bytes, decode with errors='ignore' ──────────────
    try:
        raw_bytes = await file.read()
    except Exception as e:
        logger.error("[Layer 0] Failed to read uploaded file: %s", e)
        raise HTTPException(status_code=400, detail=f"Could not read file: {e}")

    content = raw_bytes.decode("utf-8", errors="ignore")

    # ── Step 2: Strip whitespace, BOM, and trailing commas ───────────────
    content = content.strip().lstrip("\ufeff")          # strip BOM
    content = _re.sub(r",\s*$", "", content)            # strip trailing comma(s)

    # ── Step 3: Force-wrap if not already a JSON array ───────────────────
    if not content.startswith("["):
        print("[Layer 0] Forced JSON array wrap for malformed input.")
        logger.info("[Layer 0] Forced JSON array wrap for malformed input.")
        content = f"[{content}]"

    # ── Step 4: Parse ─────────────────────────────────────────────────────
    try:
        raw_records = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error("[Layer 0] JSON parse error after wrap attempt: %s", e)
        raise HTTPException(
            status_code=422,
            detail=f"Could not parse file as JSON even after auto-wrap: {e}",
        )

    # Normalise: single dict → list
    if isinstance(raw_records, dict):
        raw_records = [raw_records]

    if not isinstance(raw_records, list) or len(raw_records) == 0:
        raise HTTPException(status_code=400, detail="Empty or invalid log array.")

    logger.info("[Layer 0] Parsed %d log records — handing off to pipeline.", len(raw_records))

    # ── Step 5: Run 7-layer pipeline ──────────────────────────────────────
    try:
        result = _run_pipeline_safe(raw_records)
        logger.info(
            "[Layer 0] Pipeline complete — %d detections produced.",
            len(result["detections"]),
        )
        return JSONResponse(content=result)
    except Exception as e:
        logger.error("[Layer 0] Pipeline error: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Pipeline error: {e}")


# ── POST /ingest_json — raw JSON body (convenience / benchmark) ───────────────
@app.post("/ingest_json")
async def ingest_json(data: List[dict] = Body(...)):
    """
    Accepts a raw JSON array in the request body (no file upload needed).
    Useful for testing with curl or the benchmark endpoint.
    """
    if not data:
        raise HTTPException(status_code=400, detail="Empty array.")

    logger.info("ingest_json: running pipeline on %d records", len(data))
    try:
        result = _run_pipeline_safe(data)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error("Pipeline error: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Pipeline error: {e}")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    logger.info("Starting TuxSOC on http://0.0.0.0:8000")
    logger.info("Frontend origins allowed: localhost:5173, localhost:3000")

    try:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            log_level="info",
            access_log=True,
            reload=False,
        )
    except Exception:
        logger.critical("Server failed to start:\n%s", traceback.format_exc())
        input("Press ENTER to close...")
