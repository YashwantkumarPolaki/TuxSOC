"""
main.py — Noisy Log Fidelity Engine API
Layer 2.5 — Standalone FastAPI server

Port: 8002  (layer_0 = 8000, layer_3 = 8001)

Run:
    cd tuxsoc/backend/noisy_ingest_engine
    uvicorn main:app --host 0.0.0.0 --port 8002 --reload
"""

import os
import sys
import logging

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import requests
from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from pydantic import BaseModel
from typing import Any

from ingestor import universal_ingest
from analyzer import analyse_batch, OLLAMA_BASE_URL, OLLAMA_MODEL

logger = logging.getLogger("noisy_fidelity")
logging.basicConfig(level=logging.INFO)


def _check_ollama_on_startup() -> None:
    """Ping Ollama /api/tags and warn if the required model isn't pulled."""
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if not resp.ok:
            logger.warning(
                "Ollama health check failed: %s %s", resp.status_code, resp.reason
            )
            return
        pulled = [m.get("name", "") for m in resp.json().get("models", [])]
        # Ollama tags look like "llama3.2:latest" — match on prefix
        matched = any(m.startswith(OLLAMA_MODEL) for m in pulled)
        if matched:
            logger.info("✅  Ollama is running and model '%s' is available.", OLLAMA_MODEL)
        else:
            logger.warning(
                "⚠️  Ollama is running but model '%s' is NOT pulled. "
                "Available models: %s  — run: ollama pull %s",
                OLLAMA_MODEL,
                pulled or "(none)",
                OLLAMA_MODEL,
            )
    except requests.exceptions.ConnectionError:
        logger.warning(
            "⚠️  Ollama is NOT reachable at %s. "
            "Start it with: ollama serve",
            OLLAMA_BASE_URL,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _check_ollama_on_startup()
    yield

# ── App ───────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Noisy Log Fidelity Engine",
    description=(
        "Layer 2.5 — Ingests noisy/mislabelled CSV or Excel security logs, "
        "fuzzy-maps schema-agnostic columns, and uses a local Ollama LLM "
        "(DORA-aligned prompt) to re-classify each event with a corrected severity."
    ),
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BATCH_SIZE = 3   # keep Ollama from choking — 3 concurrent prompts max per batch


# ── Response schema ───────────────────────────────────────────────────────
class FidelityResult(BaseModel):
    event_name:          str
    explanation:         str
    recommended_actions: list[str]
    revised_severity:    str   # Low | Medium | High | Critical
    original_ip:         str
    original_user:       str
    original_action:     str
    original_severity:   str


class NoisyIngestResponse(BaseModel):
    status:          str
    file:            str
    total_processed: int
    results:         list[FidelityResult]


# ── Endpoint ──────────────────────────────────────────────────────────────
@app.post("/api/noisy-ingest", response_model=NoisyIngestResponse)
async def noisy_ingest(file: UploadFile = File(...)):
    """
    Upload a CSV or Excel file (any delimiter, any column names).
    Returns re-classified events with revised severity from Ollama.
    """
    filename = file.filename or ""

    if not filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file provided.",
        )

    # ── Read bytes ────────────────────────────────────────────────────────
    try:
        raw_bytes = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read uploaded file: {e}",
        )

    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="This file format is not supported or the file is corrupted.",
        )

    # ── Parse via universal ingestor ──────────────────────────────────────
    events: list[dict[str, Any]] = universal_ingest(raw_bytes, filename)

    if not events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "This file format is not supported or the file is corrupted. "
                "Please upload a valid CSV or Excel file with at least one data row."
            ),
        )

    # ── Analyse in batches ────────────────────────────────────────────────
    all_results: list[dict[str, Any]] = []
    for i in range(0, len(events), BATCH_SIZE):
        batch        = events[i : i + BATCH_SIZE]
        batch_results = await analyse_batch(batch)
        all_results.extend(batch_results)

    # ── Build response — map ingestor keys → FidelityResult fields ────────
    fidelity_results: list[FidelityResult] = []
    for event, result in zip(events, all_results):
        fidelity_results.append(FidelityResult(
            event_name=          result.get("event_name", "Unknown Event"),
            explanation=         result.get("explanation", ""),
            recommended_actions= result.get("recommended_actions", []),
            revised_severity=    result.get("revised_severity", "Medium"),
            # ingestor keys → response fields
            original_ip=         event.get("ip",       "N/A"),
            original_user=       event.get("user",     "N/A"),
            original_action=     event.get("action",   "N/A"),
            original_severity=   event.get("severity", "N/A"),
        ))

    return NoisyIngestResponse(
        status=          "success",
        file=            filename,
        total_processed= len(fidelity_results),
        results=         fidelity_results,
    )


# ── Health ────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":  "healthy",
        "service": "Noisy Log Fidelity Engine",
        "port":    8002,
    }


# ── Entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
