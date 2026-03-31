"""
safe_runner.py — Layer 3 AI Analysis: Safe Pipeline Wrapper
============================================================
Called by main_orchestrator._layer3_ai() to run AI analysis safely
inside the synchronous pipeline without crashing if Ollama is offline
or the Rich live-UI thread tries to start.

Entry point:
    from layer_3_ai_analysis.safe_runner import run_layer3
    result = run_layer3(detection_dict)

Returns:
    dict | None  — None when Ollama is offline or analysis fails.
    On success returns a dict with keys that main_orchestrator normalises:
    {
        "ai_analysis": {
            "intent":              str,
            "narrative":           str,
            "severity":            str,
            "cvss_vector":         dict | None,
            "kibana_query":        str | None,
            "recommended_actions": list[str],
            "cis_violations":      list[dict],
            "ai_failed":           bool,
        },
        "dora_compliance": dict | None,
        "incident_id":     str,
    }
"""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger("layer_3_ai_analysis.safe_runner")

# ── Ensure the layer_3 directory is importable ──────────────────────────────
_L3_DIR = os.path.dirname(os.path.abspath(__file__))
if _L3_DIR not in sys.path:
    sys.path.insert(0, _L3_DIR)


def _patch_rich_live() -> None:
    """
    Monkey-patch Rich's Live context so it no-ops when called from a
    background pipeline thread (avoids 'I/O operation on closed file' crashes).
    """
    try:
        from rich import live as _rich_live

        class _NoOpLive:
            def __init__(self, *a, **kw): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def update(self, *a, **kw): pass
            def start(self, *a, **kw): pass
            def stop(self, *a, **kw): pass
            def refresh(self, *a, **kw): pass

        _rich_live.Live = _NoOpLive  # type: ignore[attr-defined]
        logger.debug("[L3-safe] Rich Live patched to no-op")
    except Exception:
        pass


def run_layer3(detection: dict) -> dict | None:
    """
    Safe wrapper around ai_orchestrator.run_ai_analysis().

    1. Patches Rich Live UI so it doesn't crash the pipeline.
    2. Checks Ollama connectivity — returns None immediately if offline.
    3. Calls run_ai_analysis(detection).
    4. Catches ALL exceptions so the pipeline never crashes.

    Parameters
    ----------
    detection : partial BackendDetection dict built by main_orchestrator
                before Layer 3 runs.  Must contain at least:
                  engine_1_anomaly, engine_2_threat_intel, raw_event

    Returns
    -------
    dict with keys {ai_analysis, dora_compliance, incident_id} on success.
    None if Ollama is offline or any unrecoverable error occurs.
    """
    _patch_rich_live()

    # ── Quick Ollama connectivity check ─────────────────────────────────
    try:
        from ollama_client import check_ollama_connection
        conn = check_ollama_connection()
        if not conn.get("connected"):
            logger.debug(
                "[L3-safe] Ollama offline (%s) — skipping AI analysis",
                conn.get("error", "unreachable"),
            )
            return None
    except Exception as e:
        logger.debug("[L3-safe] Ollama check failed: %s — skipping AI", e)
        return None

    # ── Run AI analysis ─────────────────────────────────────────────────
    try:
        from ai_orchestrator import run_ai_analysis
        result = run_ai_analysis(detection)
        logger.debug(
            "[L3-safe] AI analysis complete for %s — ai_failed=%s",
            detection.get("incident_id"),
            (result.get("ai_analysis") or {}).get("ai_failed"),
        )
        return result
    except Exception as e:
        logger.warning("[L3-safe] run_ai_analysis raised: %s", e)
        return None
