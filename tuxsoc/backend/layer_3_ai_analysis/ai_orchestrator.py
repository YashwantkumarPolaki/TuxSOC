"""
ai_orchestrator.py — Layer 3: AI Cognitive Analyst
===================================================
Runs LangGraph + Ollama analysis on a single incident dict.
All Rich UI has been removed — output goes to standard logging.
"""

import sys
import os
import logging
import requests
from typing import Union

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ollama_client import check_ollama_connection, run_inference
from agent.agent_graph import build_graph
from agent.agent_state import AgentState
from prompt_builder import (
    build_dora_classification_prompt,
    build_benchmark_analysis_prompt,
    build_direct_l0_analysis_prompt,
)
from json_parser import parse_llm_response

logger = logging.getLogger("layer_3_ai_analysis")

# ── Configuration ─────────────────────────────────────────────────────────────
CVSS_LAYER_URL = "http://localhost:8004/api/v1/score"
_graph = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_observables(incident_data: dict) -> dict:
    raw_event   = incident_data.get("raw_event", {})
    engine1     = incident_data.get("engine_1_anomaly", {})
    engine2     = incident_data.get("engine_2_threat_intel", {})
    source      = incident_data.get("source", {})
    destination = incident_data.get("destination", {})
    mitre       = incident_data.get("mitre_attack", {})

    return {
        "source_ip":       raw_event.get("source_ip")      or source.get("ip"),
        "destination_ip":  raw_event.get("destination_ip") or destination.get("ip"),
        "port":            raw_event.get("port")            or destination.get("port"),
        "protocol":        raw_event.get("protocol"),
        "affected_host":   raw_event.get("affected_host"),
        "affected_user":   raw_event.get("affected_user")  or source.get("user"),
        "action":          raw_event.get("action"),
        "mitre_technique": (
            engine2.get("mitre_technique")
            or engine2.get("mitre_technique_name")
            or mitre.get("technique_id")
        ),
        "mitre_tactic": (
            engine2.get("mitre_tactic")
            or mitre.get("tactic")
        ),
        "anomaly_score": (
            engine1.get("anomaly_score")
            or incident_data.get("anomaly_detection", {}).get("pyod_score")
        ),
        "ueba_flags": engine1.get("ueba_flags", []),
    }


def _get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph


def _build_initial_state(incident_data: dict) -> AgentState:
    return {
        "incident_data":       incident_data,
        "event_id":            incident_data.get("event_id"),
        "intent":              None,
        "severity":            None,
        "cvss_vector":         None,
        "narrative":           None,
        "kibana_query":        None,
        "recommended_actions": None,
        "retry_count":         0,
        "validation_passed":   False,
        "ai_failed":           False,
        "ai_failure_reason":   None,
        "error":               None,
        "ai_analysis":         None,
    }


# ── DORA Classification ───────────────────────────────────────────────────────

def _run_dora_classification(incident_id: str, observables: dict,
                              ai_analysis: dict, incident_data: dict) -> dict:
    try:
        prompt = build_dora_classification_prompt(
            incident_id, observables, ai_analysis, incident_data
        )
        result = run_inference(prompt)
        if not result["success"]:
            raise ValueError(result["error"])
        parsed = parse_llm_response(result["response"])
        if parsed["parsed"] and isinstance(parsed["data"], dict):
            return parsed["data"]
        raise ValueError("DORA LLM response could not be parsed")
    except Exception as e:
        logger.warning("DORA classification failed: %s — returning safe default", e)
        return {
            "article_18_classification": {
                "is_major_incident":   None,
                "criteria_triggered":  [],
                "criteria_evaluation": {},
                "error":               str(e),
            },
            "article_19_initial_notification": {
                "notification_type":      "T+4h Initial Notification",
                "regulation":             "EU DORA 2022/2554 — Article 19(1)(a)",
                "reporting_standard":     "ITS 2025/302",
                "incident_id":            incident_id,
                "lei":                    "BARCLAYS-LEI-213800LBQA1Y9L22JB70",
                "incident_timestamp":     None,
                "classification_time":    None,
                "affected_services":      [],
                "initial_description":    "Classification pending — manual review required.",
                "c1_to_c6_triggers":      [],
                "containment_status":     "Unknown",
                "cross_border_impact":    None,
                "escalated_to_regulator": False,
                "error":                  str(e),
            },
        }


# ── Main entry point ──────────────────────────────────────────────────────────

def run_ai_analysis(incident_data: Union[dict, list]) -> dict:
    while isinstance(incident_data, list) and len(incident_data) > 0:
        incident_data = incident_data[0]

    observables = _extract_observables(incident_data)
    incident_id = (
        incident_data.get("incident_id")
        or incident_data.get("event_id")
        or "UNKNOWN"
    )

    logger.info("[L3] Analysing incident: %s", incident_id)

    final_state = {
        "intent":              None,
        "severity":            None,
        "cvss_vector":         None,
        "narrative":           None,
        "kibana_query":        None,
        "recommended_actions": [],
        "ai_failed":           False,
        "ai_failure_reason":   None,
        "validation_passed":   False,
    }

    is_benchmark = incident_data.get("is_benchmark_sequence", False)
    is_direct_l0 = (
        incident_data.get("is_direct_l3", False)
        or incident_data.get("source_layer") == "layer_0"
    )

    # ── Benchmark path ────────────────────────────────────────────────
    if is_benchmark:
        logger.info("[L3] Benchmark sequence — building playbook prompt")
        prompt   = build_benchmark_analysis_prompt(incident_data)
        ai_block = {
            "intent":              "BENCHMARK_SIMULATION",
            "severity":            "critical",
            "cvss_vector":         {},
            "narrative":           "AI forensic analysis for methodology and playbook generation.",
            "kibana_query":        None,
            "recommended_actions": [],
            "ai_failed":           False,
            "ai_failure_reason":   None,
            "cis_violations":      [],
            "playbook_raw":        None,
        }
        connection = check_ollama_connection()
        if not connection["connected"]:
            logger.warning("[L3] Ollama offline: %s", connection.get("error"))
            ai_block["ai_failed"]         = True
            ai_block["ai_failure_reason"] = f"Ollama unreachable: {connection.get('error')}"
        else:
            try:
                result = run_inference(prompt)
                ai_block["playbook_raw"] = result.get("response") if result.get("success") else None
            except Exception as e:
                logger.error("[L3] Benchmark inference failed: %s", e)
                ai_block["ai_failed"]         = True
                ai_block["ai_failure_reason"] = f"Benchmark inference failed: {e}"

        _push_to_layer4(incident_id, ai_block, {}, observables,
                        incident_data.get("correlated_evidence", []))
        return {
            "incident_id":     incident_id,
            "threat_summary":  "Benchmark Sequence Playbook Evaluation",
            "observables":     observables,
            "ai_analysis":     ai_block,
            "dora_compliance": {},
        }

    # ── Direct L0 triage path ─────────────────────────────────────────
    if is_direct_l0:
        logger.info("[L3] Direct L0 triage for incident: %s", incident_id)
        prompt     = build_direct_l0_analysis_prompt(incident_data)
        connection = check_ollama_connection()
        if not connection["connected"]:
            logger.warning("[L3] Ollama offline — skipping direct L0 analysis")
            return {"error": "Ollama offline"}
        result = run_inference(prompt)
        parsed = parse_llm_response(result["response"])
        ai_block = parsed["data"] if parsed["parsed"] else {"error": "Parse failed"}
        return {
            "incident_id": incident_id,
            "source":      "direct_l0_triage",
            "ai_analysis": ai_block,
        }

    # ── Standard analysis path ────────────────────────────────────────
    connection = check_ollama_connection()
    if not connection["connected"]:
        logger.warning("[L3] Ollama offline: %s", connection.get("error"))
        final_state["ai_failed"]         = True
        final_state["ai_failure_reason"] = f"Ollama unreachable: {connection.get('error')}"
        final_state["narrative"]         = (
            "AI forensic analysis unavailable — Ollama engine offline. "
            "DORA classification derived from observables only."
        )
    else:
        initial_state = _build_initial_state(incident_data)
        try:
            logger.info("[L3] Running LangGraph for incident: %s", incident_id)
            graph_result = _get_graph().invoke(initial_state)
            final_state.update({k: v for k, v in graph_result.items() if v is not None})
        except Exception as e:
            logger.error("[L3] LangGraph crash for %s: %s", incident_id, e)
            final_state["ai_failed"]         = True
            final_state["ai_failure_reason"] = f"LangGraph Crash: {e}"
            final_state["narrative"]         = (
                "AI forensic analysis failed due to a graph execution error. "
                "DORA classification derived from observables only."
            )

    engine2        = incident_data.get("engine_2_threat_intel", {})
    cis_violations = engine2.get("cis_violations", [])

    ai_block = {
        "intent":              final_state.get("intent") or "Unknown",
        "severity":            final_state.get("severity") or "Unknown",
        "cvss_vector":         final_state.get("cvss_vector") or {},
        "narrative":           final_state.get("narrative") or "No narrative available.",
        "kibana_query":        final_state.get("kibana_query"),
        "recommended_actions": final_state.get("recommended_actions", []),
        "ai_failed":           final_state.get("ai_failed", False),
        "ai_failure_reason":   final_state.get("ai_failure_reason"),
        "cis_violations":      cis_violations,
    }

    logger.info("[L3] Running DORA classification for incident: %s", incident_id)
    dora_report = _run_dora_classification(
        incident_id, observables, ai_block, incident_data
    )

    if not final_state.get("ai_failed") and final_state.get("validation_passed"):
        _push_to_layer4(incident_id, ai_block, dora_report, observables,
                        incident_data.get("correlated_evidence", []))

    logger.info("[L3] Analysis complete for incident: %s  ai_failed=%s",
                incident_id, final_state.get("ai_failed"))

    return {
        "incident_id":     incident_id,
        "threat_summary":  final_state.get("narrative"),
        "observables":     observables,
        "ai_analysis":     ai_block,
        "dora_compliance": dora_report,
    }


def _push_to_layer4(incident_id: str, ai_block: dict, dora_report: dict,
                    observables: dict, related_logs: list) -> None:
    """Fire-and-forget push to Layer 4 CVSS service."""
    try:
        payload = {
            "event_id":        incident_id,
            "ai_analysis":     ai_block,
            "dora_compliance": dora_report,
            "observables":     observables,
            "related_logs":    related_logs,
        }
        resp = requests.post(CVSS_LAYER_URL, json=payload, timeout=5)
        if resp.status_code == 200:
            logger.info("[L3] Layer 4 handoff OK for %s", incident_id)
        else:
            logger.warning("[L3] Layer 4 returned %s for %s", resp.status_code, incident_id)
    except Exception as e:
        logger.warning("[L3] Layer 4 push failed for %s: %s", incident_id, e)


# ── Server startup ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    logger.info("Starting tuxSOC Layer 3 AI Analyst on 0.0.0.0:8003")
    logger.info("Ollama check: %s", check_ollama_connection())

    try:
        uvicorn.run(
            "layer_3_ai_analysis.app:app",
            host="0.0.0.0",
            port=8003,
            log_level="info",
            access_log=True,
        )
    except Exception:
        logger.critical("Layer 3 startup FAILED:\n%s", traceback.format_exc())
        print("\nPress ENTER to close...")
        input()
