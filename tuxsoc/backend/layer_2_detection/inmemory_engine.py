"""
inmemory_engine.py — Layer 2: In-Memory Detection Engine
=========================================================
Runs all 3 detection engines on a single enriched event (Layer 1 output).
This is the in-memory counterpart to detection_orchestrator.py (which is
ES-backed). Called by main_orchestrator._layer2_detect().

Engine execution order:
  1. Rules Registry  — maps enriched fields to a rule_id
  2. Engine 1 Anomaly — PyOD score + UEBA flags (reads L1 behavioral features)
  3. Engine 2 Threat Intel — IOC matching + MITRE mapping
  (Engine 3 Correlation is handled at batch level in inmemory_correlator.py)

Enriched Layer 1 fields consumed:
  _l1_entropy          — boosts anomaly score for high-entropy actions
  _l1_is_internal      — suppresses IOC bonus for internal-only traffic
  _l1_velocity_score   — feeds into UEBA deviation
  _l1_off_hours        — adds off_hours_activity UEBA flag
  _l1_risk_keywords    — used for rule_id selection
  behavioral_features  — deviation_score used as anomaly base
  identity_features    — user/risk_level for UEBA
"""

from __future__ import annotations
import re

from layer_2_detection.engine_1_anomaly.pyod_detector import compute_anomaly_score
from layer_2_detection.engine_2_threat_intel.mitre_mapper import get_mitre_mapping

# ioc_matcher imports elasticsearch — guard gracefully
try:
    from layer_2_detection.engine_2_threat_intel.ioc_matcher import match_iocs as _match_iocs
    def match_iocs(source_ip=None, destination_ip=None, **_):
        return _match_iocs(source_ip=source_ip, destination_ip=destination_ip)
except ImportError:
    def match_iocs(source_ip=None, destination_ip=None, **_):  # type: ignore[misc]
        """Fallback when elasticsearch package is not installed."""
        _STATIC_BLACKLIST = {"194.5.6.7", "185.192.69.5", "45.33.22.11",
                             "203.0.113.50", "114.114.114.114", "45.45.45.45"}
        matches = []
        for ip in filter(None, [source_ip, destination_ip]):
            if ip in _STATIC_BLACKLIST:
                matches.append(f"blacklist_hit_{ip}")
        return {"ioc_matches": matches, "threat_intel_match": len(matches) > 0}


# ── Rule selector ─────────────────────────────────────────────────────────────

_ACTION_RULE_MAP: list[tuple[re.Pattern, str]] = [
    # Web
    (re.compile(r"union.select|1=1|waitfor.delay|sql.inject", re.I), "WEB_SQLI"),
    (re.compile(r"/etc/passwd|/etc/shadow|\.\.\/|cmd\.exe|bash\s+-i|;\s*wget|;\s*curl", re.I), "WEB_CMDI"),
    (re.compile(r"\.\./|\.\.%2f|boot\.ini|/etc/shadow", re.I), "WEB_LFI"),
    (re.compile(r"<script|javascript:|onerror=|onload=", re.I), "WEB_XSS"),
    (re.compile(r"sqlmap|nikto|nmap|dirbuster|gobuster|masscan|python-requests", re.I), "WEB_SCANNER"),
    (re.compile(r"169\.254\.169\.254|metadata\.google|100\.100\.100\.200", re.I), "WEB_SSRF"),
    # Auth
    (re.compile(r"brute.?force|credential.stuff|>20.fail|failed.login", re.I), "AUTH_BRUTEFORCE"),
    (re.compile(r"password.spray|spray", re.I), "AUTH_SPRAY"),
    (re.compile(r"mfa.fatigue|mfa.prompt|mfa.push", re.I), "AUTH_MFA_FATIGUE"),
    (re.compile(r"priv.abuse|admin.login|root.login|privileged", re.I), "AUTH_PRIV_ABUSE"),
    # Endpoint
    (re.compile(r"ransomware|vssadmin.delete|mass.file.modif|\.encrypted|\.locked", re.I), "EP_RANSOMWARE"),
    (re.compile(r"powershell.*bypass|encodedcommand|invoke-expression|iex\b|downloadstring|-windowstyle.hidden", re.I), "EP_LOLBIN"),
    (re.compile(r"lsass|mimikatz|procdump|sekurlsa", re.I), "EP_CREDENTIAL_DUMP"),
    (re.compile(r"wevtutil.cl|clear-eventlog|event.log.clear", re.I), "EP_DEF_EVASION"),
    (re.compile(r"schtasks.*/create|currentversion\\run|cron.job.creat", re.I), "EP_PERSISTENCE"),
    # Network
    (re.compile(r"port.scan|>50.port|nmap.scan", re.I), "NET_PORTSCAN"),
    (re.compile(r"c2.beacon|beacon|periodic.connect", re.I), "NET_C2_BEACON"),
    (re.compile(r"dns.tunnel|dns.txt|long.subdomain", re.I), "NET_DNS_TUNNEL"),
    (re.compile(r"exfil|>1gb|large.transfer|filesync", re.I), "NET_EXFIL"),
    (re.compile(r"lateral.mov|smb.445|rdp.3389|wmi.exec|pass.the.hash", re.I), "NET_LATERAL"),
]

# Keyword-based rule overrides (checked before action regex)
_KEYWORD_RULE_MAP: list[tuple[str, str]] = [
    ("new-inboxrule",       "AUTH_PRIV_ABUSE"),
    ("inboxrule",           "AUTH_PRIV_ABUSE"),
    ("forwardto",           "AUTH_PRIV_ABUSE"),
    ("filedownloaded",      "NET_EXFIL"),
    ("filesyncdownloaded",  "NET_EXFIL"),
    ("mailitemsaccessed",   "AUTH_PRIV_ABUSE"),
    ("sign-in",             "AUTH_PRIV_ABUSE"),
    ("risky sign-in",       "AUTH_PRIV_ABUSE"),
]


def _select_rule_id(enriched: dict) -> str:
    """
    Select the best-matching rule_id from the enriched event.
    Priority: risk_keywords from L1 → action regex → fallback.
    """
    action = (enriched.get("_l1_action") or enriched.get("OperationName")
              or enriched.get("Operation") or "").lower()

    # 1. L1 risk keywords (already extracted)
    risk_kws = enriched.get("_l1_risk_keywords") or []
    for kw in risk_kws:
        for keyword, rule_id in _KEYWORD_RULE_MAP:
            if keyword in kw:
                return rule_id

    # 2. Action keyword shortcuts
    for keyword, rule_id in _KEYWORD_RULE_MAP:
        if keyword in action:
            return rule_id

    # 3. Action regex
    for pattern, rule_id in _ACTION_RULE_MAP:
        if pattern.search(action):
            return rule_id

    # 4. Log-family fallback
    family = enriched.get("log_family") or enriched.get("log_type") or "network"
    _FAMILY_FALLBACK = {
        "auth":     "AUTH_PRIV_ABUSE",
        "web":      "WEB_SCANNER",
        "endpoint": "EP_LOLBIN",
        "iot":      "NET_C2_BEACON",
        "network":  "NET_PORTSCAN",
    }
    return _FAMILY_FALLBACK.get(family, "NET_PORTSCAN")


# ── UEBA flag builder ─────────────────────────────────────────────────────────

def _build_ueba_flags(enriched: dict, rule_id: str) -> list[str]:
    """
    Derive UEBA flags from Layer 1 enriched features.
    These augment the rule-level flags already in pyod_detector.
    """
    flags: list[str] = []

    # Off-hours activity (from temporal engine)
    temporal = enriched.get("temporal_features") or {}
    if temporal.get("off_hours") or enriched.get("_l1_off_hours"):
        flags.append("off_hours_activity")

    # High velocity from same source
    behavioral = enriched.get("behavioral_features") or {}
    velocity = behavioral.get("velocity_score") or enriched.get("_l1_velocity_score") or 0.0
    if velocity >= 0.5:
        flags.append("high_velocity_source")

    # High-risk identity signals
    risk_level = (behavioral.get("risk_level") or "").lower()
    risk_state = (behavioral.get("risk_state") or "").lower()
    if risk_level in ("high", "medium"):
        flags.append("risky_signin")
    if risk_state == "atrisk":
        flags.append("suspicious_ip")

    # High-entropy action (obfuscation indicator)
    entropy = enriched.get("_l1_entropy") or 0.0
    if entropy >= 4.5:
        flags.append("high_entropy_action")

    # Risk keywords found by L1
    if enriched.get("_l1_risk_keywords"):
        flags.append("risk_keyword_match")

    return flags


# ── Risk engine ───────────────────────────────────────────────────────────────

_SEV_THRESHOLDS = [
    (0.85, "CRITICAL"),
    (0.70, "HIGH"),
    (0.55, "MEDIUM"),
    (0.0,  "LOW"),
]


def _compute_risk(anomaly_score: float, ioc_match: bool,
                  ueba_flags: list[str]) -> dict:
    score = anomaly_score
    if ioc_match:
        score = min(1.0, score + 0.05)
    if "risky_signin" in ueba_flags or "suspicious_ip" in ueba_flags:
        score = min(1.0, score + 0.03)

    for threshold, sev in _SEV_THRESHOLDS:
        if score >= threshold:
            return {
                "risk_score":  round(score, 4),
                "severity":    sev,
                "confidence":  round(min(1.0, score + 0.1), 2),
                "components":  {
                    "anomaly_score": anomaly_score,
                    "ioc_bonus":     0.05 if ioc_match else 0.0,
                },
            }
    return {"risk_score": 0.1, "severity": "LOW", "confidence": 0.5, "components": {}}


# ── Public entry point ────────────────────────────────────────────────────────

def run_layer2(enriched: dict) -> dict:
    """
    Run all Layer 2 detection engines on a single enriched event.

    Parameters
    ----------
    enriched : dict
        Output of layer_1_feature_engineering.feature_orchestrator.run_feature_engineering()

    Returns
    -------
    dict with keys:
        engine_1_anomaly      — anomaly scoring block
        engine_2_threat_intel — IOC + MITRE block
        _layer2_risk          — composite risk score
        _rule_id              — matched rule ID
    """
    # ── Step 1: Select rule ───────────────────────────────────────────
    rule_id = _select_rule_id(enriched)

    # ── Step 2: Build UEBA flags from L1 features ─────────────────────
    ueba_flags = _build_ueba_flags(enriched, rule_id)

    # ── Step 3: Engine 1 — Anomaly scoring ───────────────────────────
    # Boost base score with L1 deviation_score if it's higher
    behavioral = enriched.get("behavioral_features") or {}
    deviation  = behavioral.get("deviation_score") or enriched.get("_l1_velocity_score") or 0.0

    e1 = compute_anomaly_score(rule_id, ueba_flags)

    # If L1 deviation_score is higher than the rule base, blend it in
    if deviation > e1["anomaly_score"]:
        blended = round(min(1.0, e1["anomaly_score"] * 0.7 + deviation * 0.3), 4)
        e1 = {**e1, "anomaly_score": blended, "pyod_score": blended,
              "is_outlier": blended >= 0.70, "anomaly_flagged": blended >= 0.60}

    # ── Step 4: Engine 2 — Threat Intel ──────────────────────────────
    source_ip = enriched.get("_l1_source_ip") or enriched.get("source_ip")
    dest_ip   = enriched.get("_l1_dest_ip") or enriched.get("destination_ip")

    # Don't flag internal-only traffic as IOC match
    is_internal = enriched.get("_l1_is_internal", False)
    ioc_result = match_iocs(
        source_ip=source_ip if not is_internal else None,
        destination_ip=dest_ip,
    )
    mitre = get_mitre_mapping(rule_id)

    e2 = {
        **ioc_result,
        **mitre,
        "rule_id":         rule_id,
        "rule_name":       rule_id.replace("_", " ").title(),
        "rule_confidence": round(e1["anomaly_score"], 2),
        "mitre_url":       f"https://attack.mitre.org/techniques/{mitre.get('mitre_technique', 'T0000').split('.')[0]}/",
    }

    # ── Step 5: Risk scoring ──────────────────────────────────────────
    risk = _compute_risk(e1["anomaly_score"], ioc_result["threat_intel_match"], ueba_flags)

    return {
        "engine_1_anomaly":      e1,
        "engine_2_threat_intel": e2,
        "_layer2_risk":          risk,
        "_rule_id":              rule_id,
    }
