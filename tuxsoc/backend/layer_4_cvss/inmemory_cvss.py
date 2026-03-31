"""
inmemory_cvss.py — Layer 4: In-Memory CVSS Scoring
====================================================
Computes a CVSS v3.1-inspired base score and severity classification
for a single detection, using the engine_1_anomaly and
engine_2_threat_intel outputs from Layer 2.

Called by main_orchestrator._layer4_cvss().

Scoring formula:
  base = anomaly_score * 10
  ioc_bonus = +0.5 if threat_intel_match
  tactic_bonus = +0.3 for high-impact tactics (Exfiltration, Impact, etc.)
  master_bonus = +0.5 if is_master incident
  score = min(10.0, base + ioc_bonus + tactic_bonus + master_bonus)

DORA compliance is flagged when:
  - anomaly_score > 0.7, OR
  - mitre_tactic is in the high-impact set, OR
  - is_master is True
"""

from __future__ import annotations

_HIGH_IMPACT_TACTICS = {
    "Exfiltration", "Impact", "Lateral Movement", "Credential Access",
    "Collection", "Command and Control", "Multi-Stage BEC Kill Chain",
}

_SEV_THRESHOLDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.0, "LOW"),
]


def score_detection(
    anomaly_score: float,
    mitre_tactic: str = "",
    mitre_technique: str = "",
    threat_intel_match: bool = False,
    is_master: bool = False,
    ai_cvss_vector: str | None = None,
) -> dict:
    """
    Compute the layer4_cvss block for a single detection.

    Parameters
    ----------
    anomaly_score      : 0.0–1.0 from engine_1_anomaly
    mitre_tactic       : MITRE tactic string from engine_2_threat_intel
    mitre_technique    : MITRE technique ID (unused in formula, kept for schema)
    threat_intel_match : True if IOC match found
    is_master          : True for batch master incidents
    ai_cvss_vector     : Optional CVSS vector string from Layer 3 AI

    Returns
    -------
    dict matching the layer4_cvss schema:
        base_score, severity, requires_auto_block, dora_compliance
    """
    base = anomaly_score * 10
    ioc_bonus    = 0.5 if threat_intel_match else 0.0
    tactic_bonus = 0.3 if mitre_tactic in _HIGH_IMPACT_TACTICS else 0.0
    master_bonus = 0.5 if is_master else 0.0

    score = round(min(10.0, base + ioc_bonus + tactic_bonus + master_bonus), 1)

    # Severity classification
    severity = "LOW"
    for threshold, sev in _SEV_THRESHOLDS:
        if score >= threshold:
            severity = sev
            break

    # DORA compliance flag
    dora = (
        anomaly_score > 0.7
        or mitre_tactic in _HIGH_IMPACT_TACTICS
        or is_master
    )

    return {
        "base_score":          score,
        "severity":            severity,
        "requires_auto_block": score >= 7.0,
        "dora_compliance":     dora,
    }
