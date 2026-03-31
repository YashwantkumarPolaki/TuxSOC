"""
shared/schemas.py
-----------------
Pydantic models shared across Layer 3 → Layer 4 → Layer 5 HTTP handoffs.

These are used by the standalone FastAPI microservices (cvss_orchestrator,
response_orchestrator).  The in-memory pipeline (main_orchestrator) bypasses
HTTP and calls the layer functions directly, so this file only matters when
running the services individually.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ── CIS Violation (nested inside AIAnalysisBlock) ────────────────────────────

class CISViolation(BaseModel):
    benchmark_id: str = ""
    title:        str = ""
    severity:     str = "LOW"
    device_type:  str = ""
    mitre_tactic: str = ""
    rationale:    str = ""
    cvss_impact:  Dict[str, str] = Field(default_factory=dict)


# ── AI Analysis block sent from Layer 3 → Layer 4 ────────────────────────────

class AIAnalysisBlock(BaseModel):
    intent:              Optional[str]            = None
    severity:            Optional[str]            = None
    narrative:           Optional[str]            = None
    kibana_query:        Optional[str]            = None
    recommended_actions: List[str]                = Field(default_factory=list)
    cvss_vector:         Optional[Dict[str, str]] = None
    cis_violations:      List[CISViolation]       = Field(default_factory=list)
    ai_failed:           bool                     = False
    ai_failure_reason:   Optional[str]            = None
    playbook_raw:        Optional[str]            = None


# ── Layer 3 → Layer 4 input ───────────────────────────────────────────────────

class LLMIncidentInput(BaseModel):
    event_id:        str
    ai_analysis:     AIAnalysisBlock
    dora_compliance: Optional[Any]  = None
    observables:     Optional[Dict[str, Any]] = None
    related_logs:    Optional[Any]  = None


# ── Layer 4 → Layer 5 output ──────────────────────────────────────────────────

class ScoredIncidentOutput(BaseModel):
    event_id:            str
    base_score:          float
    severity:            str
    requires_auto_block: bool
    dora_compliance:     Optional[Any] = None


# ── Layer 4 → Layer 5 input ───────────────────────────────────────────────────

class Layer5Input(BaseModel):
    event_id:            str
    base_score:          float
    severity:            str
    requires_auto_block: bool
    attacker_ip:         Optional[str] = "Unknown"
    affected_entity:     Optional[str] = "Unknown"
    intent:              Optional[str] = "Unknown Threat"
    kibana_query:        Optional[str] = None
    related_logs:        Optional[Any] = None
    dora_compliance:     Optional[Any] = None
    playbook_raw:        Optional[str] = None
