"""
main_orchestrator.py — TuxSOC Master Pipeline Orchestrator
===========================================================
Drives the full 6-layer pipeline in-memory from a list of raw records.

Pipeline:
  Layer 0  — Ingestion / Normalisation  (ingestion.log_normalizer)
  Layer 1  — Feature Engineering        (layer_1_feature_engineering)
  Layer 2  — Detection & Risk Scoring   (layer_2_detection.inmemory_engine)
               └─ mitre_mapper.py       real MITRE ATT&CK DB (50+ techniques)
               └─ rules_registry.py     20 detection rules with weights
               └─ risk_engine.py        composite risk formula
  Layer 3  — AI Analysis                (layer_3_ai_analysis.safe_runner)
               └─ ai_orchestrator.py    LangGraph + Ollama (auto-detected)
               └─ Graceful fallback if Ollama offline
  Layer 4  — CVSS Scoring               (layer_4_cvss.inmemory_cvss)
               └─ Real CVSS v3.1 scorer when `cvss` package available
               └─ DORA compliance derived from tactic + anomaly score
  Layer 5  — Correlation + Playbooks    (layer_2_detection.inmemory_correlator)
               └─ Multi-event attack_timeline linked by IP/user/5-min window
               └─ BEC kill-chain detection + master incident collapse

Entry point:
    from main_orchestrator import run_pipeline
    detections = run_pipeline(raw_records, session_id)
"""

import hashlib
import logging
import sys
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("main_orchestrator")

# ── Pipeline status tracker (read by /pipeline/status endpoint) ──────────
_pipeline_status: dict[str, Any] = {
    "layer_0": "idle", "layer_1": "idle", "layer_2": "idle",
    "layer_3": "idle", "layer_4": "idle", "layer_5": "idle",
    "last_run": None,  "records_processed": 0,
}


def get_pipeline_status() -> dict:
    return dict(_pipeline_status)


# ── Helpers ───────────────────────────────────────────────────────────────

def _safe(val, fallback=None):
    if val is None or val == "" or val == 0:
        return fallback
    return val


def _dig(record: dict, *paths):
    """Search record, raw_event, and additional_fields for the first non-empty value."""
    targets = [record]
    raw = record.get("raw_event")
    if isinstance(raw, dict):
        targets.append(raw)
    add = record.get("additional_fields")
    if isinstance(add, dict):
        targets.append(add)

    for path in paths:
        keys = path if isinstance(path, (list, tuple)) else [path]
        for target in targets:
            cur = target
            for k in keys:
                if not isinstance(cur, dict):
                    cur = None
                    break
                cur = cur.get(k)
            if cur is not None and cur != "" and cur != 0:
                return cur
    return None


def _make_incident_id(record: dict, idx: int) -> str:
    src = record.get("source_ip") or record.get("src_ip") or str(idx)
    ts  = record.get("timestamp") or record.get("@timestamp") or ""
    return "INC-" + hashlib.md5(f"{src}-{ts}-{idx}".encode()).hexdigest()[:12].upper()


# ── Layer 2 — real detection engine (mitre_mapper + rules_registry + risk_engine) ──

def _layer2_detect(enriched: dict) -> dict:
    """
    Delegate to layer_2_detection.inmemory_engine which uses:
      - rules_registry.py  (20 real detection rules)
      - mitre_mapper.py    (full MITRE ATT&CK technique DB)
      - risk_engine.py     (composite risk formula)
    Falls back to a minimal stub if the import fails.
    """
    try:
        from layer_2_detection.inmemory_engine import run_layer2
        return run_layer2(enriched)
    except Exception as e:
        logger.warning("Layer 2 real engine failed (%s) — using minimal fallback", e)
        # Minimal safe fallback
        anomaly = float((enriched.get("behavioral_features") or {}).get("deviation_score") or 0.1)
        return {
            "engine_1_anomaly": {
                "pyod_score": anomaly, "is_outlier": anomaly >= 0.7,
                "ueba_flags": [], "anomaly_score": anomaly, "anomaly_flagged": anomaly >= 0.55,
            },
            "engine_2_threat_intel": {
                "ioc_matches": [], "threat_intel_match": False,
                "mitre_tactic": "Unknown", "mitre_technique": "Unknown",
                "mitre_technique_name": "Unknown", "mitre_url": "",
                "rule_id": "FALLBACK", "rule_name": "Fallback", "rule_confidence": 0.5,
            },
            "_layer2_risk": {"risk_score": anomaly * 0.5, "severity": "LOW",
                             "confidence": 0.5, "components": {}},
            "_layer2_error": str(e),
        }


# ── Layer 5 — Playbook Engine ─────────────────────────────────────────────

# Full playbook library keyed by playbook_id
_PLAYBOOKS: dict[str, dict] = {
    "PB-001-ACCOUNT-COMPROMISE": {
        "id":    "PB-001-ACCOUNT-COMPROMISE",
        "title": "Account Compromise & Credential Theft Response",
        "tactic_match": ["Defense Evasion", "Credential Access", "Initial Access"],
        "severity_floor": "MEDIUM",
        "steps": [
            "Immediately disable the compromised account in Azure AD / Active Directory",
            "Force a global sign-out of all active sessions for the affected user",
            "Reset credentials and enforce MFA re-enrollment before re-activation",
            "Review Azure AD sign-in logs for the past 30 days for anomalous locations",
            "Check for any new inbox rules, mail forwarding, or delegate access added",
            "Audit all files accessed or downloaded during the suspicious session window",
            "Notify the affected user and their line manager via out-of-band channel",
            "Escalate to CISO if RiskLevel is 'high' or source IP is foreign/Tor exit node",
        ],
        "auto_remediation": [
            "Revoke all OAuth tokens for the affected account",
            "Block source IP at perimeter firewall if flagged as suspicious",
            "Trigger conditional access policy to require compliant device on next login",
        ],
    },
    "PB-002-DATA-EXFILTRATION": {
        "id":    "PB-002-DATA-EXFILTRATION",
        "title": "Data Exfiltration & Leak Response",
        "tactic_match": ["Exfiltration", "Collection"],
        "severity_floor": "HIGH",
        "steps": [
            "Immediately isolate the source host from all network segments",
            "Capture a full memory dump and disk image before any remediation",
            "Identify all files accessed or downloaded in the exfiltration window",
            "Check SharePoint / OneDrive audit logs for bulk download patterns",
            "Review outbound network flows for large transfers to external IPs",
            "Notify Data Protection Officer (DPO) — GDPR/DORA 72-hour clock may apply",
            "Preserve all evidence in a forensic chain-of-custody container",
            "Submit IOCs (destination IPs, file hashes) to threat intel sharing platform",
        ],
        "auto_remediation": [
            "Apply DLP policy to block further outbound transfers from affected host",
            "Revoke SharePoint external sharing links created in the incident window",
            "Quarantine downloaded files if endpoint DLP agent is deployed",
        ],
    },
    "PB-003-LATERAL-MOVEMENT": {
        "id":    "PB-003-LATERAL-MOVEMENT",
        "title": "Lateral Movement & Privilege Escalation Response",
        "tactic_match": ["Lateral Movement", "Persistence"],
        "severity_floor": "HIGH",
        "steps": [
            "Map all hosts the attacker has touched using SMB/RDP/WMI logs",
            "Isolate each compromised host from the network segment immediately",
            "Capture memory dumps on all affected hosts before rebooting",
            "Reset all service account credentials used on the affected segment",
            "Audit sudoers / local admin group membership on all Linux/Windows hosts",
            "Check for new scheduled tasks, services, or registry run keys",
            "Run EDR full scan on all hosts in the blast radius",
            "Escalate to Incident Response team — this indicates active intrusion",
        ],
        "auto_remediation": [
            "Block SMB (445) and RDP (3389) between internal segments via firewall rule",
            "Disable NTLM authentication on affected domain controllers",
            "Force Kerberos ticket renewal for all accounts in the affected OU",
        ],
    },
    "PB-004-RANSOMWARE": {
        "id":    "PB-004-RANSOMWARE",
        "title": "Ransomware Pre-Staging & Execution Response",
        "tactic_match": ["Impact", "Execution"],
        "severity_floor": "CRITICAL",
        "steps": [
            "IMMEDIATE: Isolate ALL affected hosts from every network segment",
            "Do NOT reboot — preserve volatile memory for forensic analysis",
            "Capture full memory dump using WinPMEM or equivalent tool",
            "Identify patient zero and the initial infection vector",
            "Check for vssadmin shadow copy deletion commands in event logs",
            "Submit payload hash to sandbox (Any.run / Cuckoo) for family identification",
            "Notify CISO and activate Incident Response retainer within 15 minutes",
            "Assess backup integrity — verify last known-good backup before restoration",
        ],
        "auto_remediation": [
            "Trigger EDR kill-switch to terminate suspicious process trees",
            "Block C2 destination IPs at perimeter firewall immediately",
            "Snapshot all VMs in the affected segment before any remediation",
        ],
    },
    "PB-005-BRUTE-FORCE": {
        "id":    "PB-005-BRUTE-FORCE",
        "title": "Brute Force & Password Spray Response",
        "tactic_match": ["Credential Access"],
        "severity_floor": "MEDIUM",
        "steps": [
            "Block the source IP at the perimeter firewall immediately",
            "Check if any login attempts succeeded — review auth logs for the window",
            "Force password reset for all accounts that received >5 failed attempts",
            "Enable account lockout policy if not already active (threshold: 10 attempts)",
            "Review if source IP is a Tor exit node or known proxy — escalate if so",
            "Enable adaptive authentication for high-risk geographies",
            "Alert affected users to change passwords via out-of-band notification",
        ],
        "auto_remediation": [
            "Apply rate limiting to /auth endpoint (5 req/min per IP)",
            "Block entire /24 subnet if Tor exit node confirmed",
            "Trigger CAPTCHA challenge for all login attempts from flagged IP range",
        ],
    },
    "PB-006-INBOX-RULE-ABUSE": {
        "id":    "PB-006-INBOX-RULE-ABUSE",
        "title": "Malicious Inbox Rule & Email Forwarding Response",
        "tactic_match": ["Defense Evasion", "Collection"],
        "severity_floor": "HIGH",
        "steps": [
            "Immediately delete the suspicious inbox rule from the affected mailbox",
            "Check if any emails were forwarded externally — review mail flow logs",
            "Audit all inbox rules created in the last 30 days for the affected user",
            "Verify the external forwarding address is not a known threat actor domain",
            "Review what emails matched the rule criteria (invoice, wire transfer, etc.)",
            "Notify the affected user and Finance team if financial keywords were targeted",
            "Check for BEC (Business Email Compromise) indicators in recent correspondence",
            "Submit the external domain to threat intel for reputation check",
        ],
        "auto_remediation": [
            "Disable external email forwarding at the tenant level via Exchange policy",
            "Block the external forwarding domain at the email gateway",
            "Enable mailbox audit logging if not already active",
        ],
    },
    "PB-000-GENERIC": {
        "id":    "PB-000-GENERIC",
        "title": "Generic Security Incident Response",
        "tactic_match": [],
        "severity_floor": "LOW",
        "steps": [
            "Review the raw log entry and correlate with SIEM for additional context",
            "Identify the affected user, host, and source IP from the detection",
            "Check for related events in the same time window (±15 minutes)",
            "Assess whether the activity is authorised — verify with the asset owner",
            "Escalate to Tier-2 analyst if the action string contains suspicious keywords",
            "Document findings in the ticket notes for audit trail",
        ],
        "auto_remediation": [
            "Flag the source IP for enhanced monitoring for 24 hours",
            "Add event to watchlist for correlation with future detections",
        ],
    },
}

# Tactic → playbook_id priority mapping
_TACTIC_TO_PLAYBOOK: list[tuple[str, str]] = [
    ("Exfiltration",       "PB-002-DATA-EXFILTRATION"),
    ("Collection",         "PB-002-DATA-EXFILTRATION"),
    ("Lateral Movement",   "PB-003-LATERAL-MOVEMENT"),
    ("Persistence",        "PB-003-LATERAL-MOVEMENT"),
    ("Impact",             "PB-004-RANSOMWARE"),
    ("Execution",          "PB-004-RANSOMWARE"),
    ("Credential Access",  "PB-005-BRUTE-FORCE"),
    ("Defense Evasion",    "PB-001-ACCOUNT-COMPROMISE"),
    ("Initial Access",     "PB-001-ACCOUNT-COMPROMISE"),
]

# Event-type keyword → playbook override (checked before tactic)
_ACTION_TO_PLAYBOOK: list[tuple[str, str]] = [
    ("new-inboxrule",      "PB-006-INBOX-RULE-ABUSE"),
    ("inbox rule",         "PB-006-INBOX-RULE-ABUSE"),
    ("forwardto",          "PB-006-INBOX-RULE-ABUSE"),
    ("ransomware",         "PB-004-RANSOMWARE"),
    ("vssadmin",           "PB-004-RANSOMWARE"),
    ("mimikatz",           "PB-004-RANSOMWARE"),
    ("lsass",              "PB-004-RANSOMWARE"),
    ("brute",              "PB-005-BRUTE-FORCE"),
    ("spray",              "PB-005-BRUTE-FORCE"),
    ("login_failed",       "PB-005-BRUTE-FORCE"),
    ("filedownloaded",     "PB-002-DATA-EXFILTRATION"),
    ("exfil",              "PB-002-DATA-EXFILTRATION"),
    ("lateral",            "PB-003-LATERAL-MOVEMENT"),
    ("sign-in",            "PB-001-ACCOUNT-COMPROMISE"),
    ("mailitemsaccessed",  "PB-001-ACCOUNT-COMPROMISE"),
]


def _layer5_playbook(
    action: str,
    tactic: str,
    risk_sev: str,
    log_type: str = "",
    affected_user: str | None = None,
    source_ip: str | None = None,
    anomaly_score: float = 0.0,
) -> dict:
    """
    Select and dynamically inject context into the most appropriate playbook.

    Priority:
      1. Action keyword match
      2. log_type template (auth / web / iot)
      3. MITRE tactic match
      4. Severity-based fallback

    Variable injection:
      - Playbook title and steps reference the real affected_user and source_ip
      - DORA flag only attached when anomaly_score > 0.7
    """
    import copy
    action_lower = (action or "").lower()
    tactic_lower = (tactic or "").lower()
    log_type_lower = (log_type or "").lower()
    user_label = affected_user or "unknown user"
    ip_label   = source_ip    or "unknown IP"

    # ── log_type-based templates (checked before action keywords) ─────────
    _AUTH_FAMILIES = {"auth", "azure_ad", "office365", "sharepoint"}
    _LOG_TYPE_TEMPLATES: dict[str, dict] = {
        "auth": {
            "id":    "PB-LT-AUTH",
            "title": f"Account Takeover Response — {user_label}",
            "steps": [
                f"Disable the account for {user_label} in Azure AD / Active Directory immediately",
                f"Revoke all active sessions and OAuth tokens for {user_label}",
                f"Block source IP {ip_label} at the perimeter firewall",
                "Force MFA re-enrollment before re-activating the account",
                "Review sign-in logs for the past 30 days for anomalous locations",
                "Check for new inbox rules, mail forwarding, or delegate access",
                f"Notify {user_label} and their line manager via out-of-band channel",
            ],
            "auto_remediation": [
                f"Revoke all OAuth tokens for {user_label} via Microsoft Graph API",
                f"Block {ip_label} at perimeter firewall",
                "Trigger Conditional Access: require compliant device on next login",
            ],
        },
        "web": {
            "id":    "PB-LT-WEB",
            "title": f"Web Attack Response — {ip_label}",
            "steps": [
                f"Block source IP {ip_label} at the WAF and perimeter firewall immediately",
                "Capture and preserve all HTTP request logs for the attack window",
                "Identify the targeted endpoint and assess data exposure",
                "Check for SQL injection, XSS, or path traversal payloads in request body",
                "Review application error logs for successful exploitation indicators",
                "Patch or temporarily disable the vulnerable endpoint if exploitation confirmed",
                "Notify the application owner and security team",
            ],
            "auto_remediation": [
                f"Apply WAF rule to block {ip_label} and its /24 subnet",
                "Enable rate limiting on the targeted endpoint (10 req/min)",
                "Trigger SIEM alert for further requests from this IP range",
            ],
        },
        "iot": {
            "id":    "PB-LT-IOT",
            "title": f"IoT Device Compromise Response — {ip_label}",
            "steps": [
                f"Isolate the device at {ip_label} from the network segment immediately",
                "Capture device firmware version and last-known-good configuration",
                "Check for unauthorised firmware updates or configuration changes",
                "Review device telemetry for anomalous command sequences",
                "Rotate all device credentials and API keys",
                "Assess whether the device was used as a pivot point for lateral movement",
                "Notify the OT/IoT security team and device vendor",
            ],
            "auto_remediation": [
                f"Quarantine device {ip_label} via network ACL",
                "Disable remote management interface until firmware is verified",
                "Push credential rotation via device management platform",
            ],
        },
    }

    # Resolve base playbook
    pb: dict | None = None

    # 1. log_type template match
    if log_type_lower in _AUTH_FAMILIES:
        pb = _LOG_TYPE_TEMPLATES["auth"]
    elif log_type_lower in _LOG_TYPE_TEMPLATES:
        pb = _LOG_TYPE_TEMPLATES[log_type_lower]
    else:
        # 2. Action keyword match
        for keyword, pb_id in _ACTION_TO_PLAYBOOK:
            if keyword in action_lower:
                pb = copy.deepcopy(_PLAYBOOKS[pb_id])
                break

        # 3. Tactic match
        if pb is None:
            for tactic_key, pb_id in _TACTIC_TO_PLAYBOOK:
                if tactic_key.lower() in tactic_lower:
                    pb = copy.deepcopy(_PLAYBOOKS[pb_id])
                    break

        # 4. Severity fallback
        if pb is None:
            pb = copy.deepcopy(
                _PLAYBOOKS["PB-001-ACCOUNT-COMPROMISE"]
                if risk_sev in ("CRITICAL", "HIGH")
                else _PLAYBOOKS["PB-000-GENERIC"]
            )

        # Inject user/IP into title for non-template playbooks
        if affected_user and affected_user not in pb["title"]:
            pb = dict(pb)  # shallow copy so we don't mutate the global
            pb["title"] = f"{pb['title']} — {user_label}"

    # ── DORA flag: only attach when anomaly_score > 0.7 ──────────────────
    if anomaly_score > 0.7:
        pb = dict(pb)
        pb["dora_flags"] = pb.get("dora_flags") or [
            "Potential DORA Article 18 trigger — high-risk event detected",
            "72-hour regulatory notification window may apply",
            "Preserve all evidence for regulatory audit trail",
        ]
    else:
        pb = dict(pb)
        pb.pop("dora_flags", None)

    # Ensure required keys exist for backward compat
    pb.setdefault("tactic_match",   [])
    pb.setdefault("severity_floor", "LOW")
    pb.setdefault("phases",         None)
    pb.setdefault("kill_chain",     None)

    return pb

# ── BEC Master Playbook ───────────────────────────────────────────────────

_BEC_MASTER_PLAYBOOK = {
    "id":    "PB-BEC-001-MASTER",
    "title": "🚨 Critical: Multi-Stage Account Takeover (BEC) Detected",
    "phases": [
        {
            "phase": "Phase 1 — Preparation & Scoping",
            "icon":  "🔍",
            "color": "#F97316",
            "steps": [
                "Confirm the suspicious sign-in from Moscow (193.168.0.50) — verify it is not a VPN or authorised travel",
                "Cross-reference the source IP against threat intel feeds (AbuseIPDB, VirusTotal)",
                "Identify all sessions initiated from this IP in the last 30 days",
                "Notify the SOC Tier-2 lead and open a P1 incident ticket immediately",
                "Preserve all Azure AD sign-in logs, Exchange audit logs, and SharePoint access logs",
            ],
        },
        {
            "phase": "Phase 2 — Containment",
            "icon":  "🛡️",
            "color": "#EF4444",
            "steps": [
                "IMMEDIATE: Disable the compromised account in Azure AD",
                "Revoke ALL active sessions and OAuth tokens for the affected account",
                "Block the attacker IP and its /24 subnet at the perimeter firewall",
                "Delete the malicious inbox rule forwarding to external address",
                "Disable external email forwarding at the Exchange Online tenant level",
                "Block the external forwarding domain at the email gateway",
                "Revoke all SharePoint external sharing links created during the incident window",
            ],
        },
        {
            "phase": "Phase 3 — Investigation",
            "icon":  "🔬",
            "color": "#EAB308",
            "steps": [
                "Audit all MailItemsAccessed events — identify which emails the attacker read",
                "Review the inbox rule parameters: financial keywords indicate BEC fraud intent",
                "Identify all files downloaded from SharePoint during the compromise window",
                "Check if any wire transfers or financial instructions were sent from the compromised account",
                "Review all emails sent FROM the account during the compromise window for impersonation",
                "Determine if any other accounts received suspicious emails from the compromised mailbox",
                "Correlate the attacker IP with any other accounts in the tenant for lateral spread",
            ],
        },
        {
            "phase": "Phase 4 — Recovery & Hardening",
            "icon":  "🔄",
            "color": "#22C55E",
            "steps": [
                "Re-enable the account only after full credential reset and MFA re-enrollment",
                "Implement Conditional Access policy: block sign-ins from high-risk countries",
                "Enable Microsoft Defender for Office 365 Safe Links and Safe Attachments",
                "Configure Azure AD Identity Protection to auto-block high-risk sign-ins",
                "Notify Finance team to verify all pending wire transfers and payment instructions",
                "Submit incident to DORA regulatory reporting if financial data was exfiltrated (72-hour clock)",
                "Conduct post-incident review and update BEC detection rules in SIEM",
            ],
        },
    ],
    "auto_remediation": [
        "Revoke all OAuth tokens for the affected account via Microsoft Graph API",
        "Block attacker IP /24 subnet at Azure Firewall via automated runbook",
        "Delete malicious inbox rule via Exchange Online PowerShell",
        "Trigger Conditional Access policy: require MFA + compliant device for next login",
        "Alert Finance Operations team via automated PagerDuty P1 escalation",
    ],
    "kill_chain": [
        {"stage": "Initial Access",  "tactic": "T1078 Valid Accounts",               "event": "Risky sign-in from foreign IP",                    "severity": "HIGH"},
        {"stage": "Persistence",     "tactic": "T1564 Hide Artifacts",               "event": "New-InboxRule forwarding to external address",      "severity": "CRITICAL"},
        {"stage": "Collection",      "tactic": "T1114 Email Collection",             "event": "MailItemsAccessed — attacker reading emails",        "severity": "HIGH"},
        {"stage": "Exfiltration",    "tactic": "T1048 Exfiltration Over Alt Protocol","event": "FileDownloaded: sensitive financial document",      "severity": "CRITICAL"},
    ],
    "dora_flags": [
        "Potential DORA Article 18 trigger — financial data accessed",
        "72-hour regulatory notification window may apply",
        "Cross-border data transfer detected",
    ],
    # Flat fields for backward compat with existing SuggestedPlaybook interface
    "steps":            [],   # populated from phases in frontend
    "auto_remediation": [
        "Revoke all OAuth tokens for the affected account via Microsoft Graph API",
        "Block attacker IP /24 subnet at Azure Firewall via automated runbook",
        "Delete malicious inbox rule via Exchange Online PowerShell",
        "Trigger Conditional Access policy: require MFA + compliant device for next login",
        "Alert Finance Operations team via automated PagerDuty P1 escalation",
    ],
    "tactic_match":   ["Initial Access", "Persistence", "Collection", "Exfiltration"],
    "severity_floor": "CRITICAL",
}
# Flatten steps from phases into the top-level steps list for backward compat
_BEC_MASTER_PLAYBOOK["steps"] = [
    step
    for phase in _BEC_MASTER_PLAYBOOK["phases"]
    for step in phase["steps"]
]


# ── Kill-chain pattern detector ───────────────────────────────────────────

_BEC_PATTERN = {
    "risky_signin": ["sign-in", "signin"],
    "inbox_rule":   ["new-inboxrule", "inbox rule", "inboxrule"],
    "exfiltration": ["filedownloaded", "filesyncdownloaded", "mailitemsaccessed"],
}


def _detect_bec_pattern(detections: list[dict]) -> bool:
    """Returns True if the detection set contains the BEC kill-chain."""
    has_risky_signin = has_inbox_rule = has_exfil = False
    for d in detections:
        action = (d.get("raw_event", {}).get("action") or "").lower()
        flags  = d.get("engine_1_anomaly", {}).get("ueba_flags", [])
        if any(k in action for k in _BEC_PATTERN["risky_signin"]):
            if "risky_signin" in flags or "suspicious_ip" in flags:
                has_risky_signin = True
        if any(k in action for k in _BEC_PATTERN["inbox_rule"]):
            has_inbox_rule = True
        if any(k in action for k in _BEC_PATTERN["exfiltration"]):
            has_exfil = True
    return has_risky_signin and has_inbox_rule and has_exfil


# ── Incident correlator ───────────────────────────────────────────────────

def _correlate_incidents(detections: list[dict]) -> list[dict]:
    """
    Group detections by affected_user within a 60-minute window.
    If a group matches the BEC kill-chain, collapse into a Master Incident.
    Otherwise return individual detections unchanged.
    """
    from collections import defaultdict
    by_user: dict[str, list[dict]] = defaultdict(list)
    ungrouped: list[dict] = []

    for d in detections:
        user = d.get("raw_event", {}).get("affected_user")
        if user and user not in ("null", "N/A", "unknown"):
            by_user[user].append(d)
        else:
            ungrouped.append(d)

    result: list[dict] = []
    for user, group in by_user.items():
        group_sorted = sorted(group, key=lambda x: x.get("timestamp", ""))
        in_window = True
        if len(group_sorted) >= 2:
            try:
                t0 = datetime.fromisoformat(group_sorted[0]["timestamp"].replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(group_sorted[-1]["timestamp"].replace("Z", "+00:00"))
                in_window = (t1 - t0).total_seconds() / 60 <= 60
            except Exception:
                pass

        if in_window and _detect_bec_pattern(group_sorted):
            result.append(_build_master_incident(user, group_sorted))
        else:
            result.extend(group_sorted)

    result.extend(ungrouped)
    return result


def _build_master_incident(user: str, detections: list[dict]) -> dict:
    """Collapse a group of related detections into one Master Incident."""
    anchor     = max(detections, key=lambda d: d.get("engine_1_anomaly", {}).get("anomaly_score", 0))
    source_ips = list({d["raw_event"]["source_ip"] for d in detections if d["raw_event"].get("source_ip")})
    timeline: list[dict] = []
    for d in detections:
        for entry in d.get("engine_3_correlation", {}).get("attack_timeline", []):
            timeline.append(entry)
    timeline.sort(key=lambda e: e.get("timestamp", ""))

    all_flags: list[str] = []
    for d in detections:
        all_flags.extend(d.get("engine_1_anomaly", {}).get("ueba_flags", []))
    ueba_flags = list(dict.fromkeys(all_flags))

    max_anomaly = max(d.get("engine_1_anomaly", {}).get("anomaly_score", 0) for d in detections)
    max_cvss    = max((d.get("layer4_cvss", {}).get("base_score", 0) or 0) for d in detections)
    ts_first    = detections[0].get("timestamp", "")
    master_id   = "MASTER-" + hashlib.md5(f"{user}-{ts_first}".encode()).hexdigest()[:10].upper()

    return {
        "incident_id":        master_id,
        "is_master":          True,
        "correlated_log_ids": [d["incident_id"] for d in detections],
        "affected_user":      user,
        "event_count":        len(detections),
        "timestamp":          ts_first,
        "log_type":           anchor.get("log_type", "auth"),
        "format":             "correlated_master",
        "raw_event": {
            **anchor.get("raw_event", {}),
            "affected_user": user,
            "action":        f"Multi-Stage BEC Attack ({len(detections)} events)",
            "source_ip":     source_ips[0] if source_ips else None,
        },
        "engine_1_anomaly": {
            **anchor.get("engine_1_anomaly", {}),
            "anomaly_score":   round(max_anomaly, 4),
            "ueba_flags":      ueba_flags,
            "anomaly_flagged": True,
            "is_outlier":      True,
        },
        "engine_2_threat_intel": {
            "ioc_matches":          [],
            "threat_intel_match":   True,
            "mitre_tactic":         "Multi-Stage BEC Kill Chain",
            "mitre_technique":      "T1078+T1564+T1114+T1048",
            "mitre_technique_name": "Valid Accounts → Hide Artifacts → Email Collection → Exfiltration",
        },
        "engine_3_correlation": {
            "event_count":     len(detections),
            "attack_timeline": timeline,
        },
        "layer4_cvss": {
            "base_score":          round(min(10.0, max_cvss if max_cvss > 0 else max_anomaly * 10), 1),
            "severity":            "CRITICAL",
            "requires_auto_block": True,
            "dora_compliance":     True,   # BEC master incidents always trigger DORA Article 18
        },
        "ai_analysis":        None,
        "suggested_playbook": _BEC_MASTER_PLAYBOOK,
        "_correlated_detections": detections,
        "_layer1":      anchor.get("_layer1", {}),
        "_layer2_risk": {"risk_score": 0.95, "severity": "CRITICAL"},
    }


# ── Layer 4 — real CVSS scoring with DORA compliance ─────────────────────

def _layer4_cvss(detection: dict) -> dict:
    """
    Delegate to layer_4_cvss.inmemory_cvss which:
      - Uses real CVSS v3.1 scorer (vector_builder + cvss package) when available
      - Derives DORA compliance from MITRE tactic + anomaly score (not null)
      - Falls back to inline formula if `cvss` package not installed
    """
    try:
        from layer_4_cvss.inmemory_cvss import score_detection
        e1 = detection.get("engine_1_anomaly", {})
        e2 = detection.get("engine_2_threat_intel", {})
        # Pull AI CVSS vector if Layer 3 ran
        ai_cvss = None
        l3 = detection.get("ai_analysis") or {}
        if isinstance(l3, dict) and l3.get("_cvss_vector"):
            ai_cvss = l3["_cvss_vector"]
        return score_detection(
            anomaly_score      = e1.get("anomaly_score", 0.0),
            mitre_tactic       = e2.get("mitre_tactic", ""),
            mitre_technique    = e2.get("mitre_technique", ""),
            threat_intel_match = e2.get("threat_intel_match", False),
            is_master          = detection.get("is_master", False),
            ai_cvss_vector     = ai_cvss,
        )
    except Exception as e:
        logger.warning("Layer 4 real engine failed (%s) — using inline formula", e)
        e1   = detection.get("engine_1_anomaly", {})
        e2   = detection.get("engine_2_threat_intel", {})
        base = e1.get("anomaly_score", 0.0) * 10
        ioc  = 0.5 if e2.get("threat_intel_match") else 0.0
        score = round(min(10.0, base + ioc), 1)
        if score >= 9.0:   sev = "CRITICAL"
        elif score >= 7.0: sev = "HIGH"
        elif score >= 4.0: sev = "MEDIUM"
        else:              sev = "LOW"
        return {"base_score": score, "severity": sev,
                "requires_auto_block": score >= 7.0, "dora_compliance": None,
                "_layer4_error": str(e)}


# ── Layer 3 — AI analysis via safe_runner ────────────────────────────────

def _layer3_ai(detection: dict) -> dict | None:
    """
    Delegate to layer_3_ai_analysis.safe_runner which:
      - Checks Ollama availability before importing ai_orchestrator
      - Patches out the Rich live-UI thread so it doesn't crash the pipeline
      - Returns {intent, summary, kibana_query} or None if Ollama offline
    """
    try:
        from layer_3_ai_analysis.safe_runner import run_layer3
        return run_layer3(detection)
    except Exception as e:
        logger.debug("Layer 3 safe_runner failed: %s", e)
        return None


# ── Shape final BackendDetection ──────────────────────────────────────────

def _shape_detection(enriched: dict, l2: dict, l3: dict | None,
                     l4: dict, idx: int) -> dict:
    """Assemble the final BackendDetection dict from all layer outputs."""
    ts = (
        _dig(enriched, "timestamp", "@timestamp", ["raw_event", "timestamp"])
        or datetime.now(timezone.utc).isoformat()
    )

    log_family = enriched.get("log_family") or enriched.get("log_type") or "network"
    family_map = {
        "azure_ad": "auth", "office365": "auth", "sharepoint": "auth",
        "web": "web", "endpoint": "endpoint", "iot": "iot",
        "network": "network", "auth": "auth", "unknown": "network",
    }
    log_type = family_map.get(log_family, "network")

    # Promote to "auth" if identity features were extracted (catches Azure AD records
    # that lack a raw_source tag but carry RiskState / UserPrincipalName fields)
    if log_type == "network" and enriched.get("identity_features"):
        log_type = "auth"

    source_ip     = _dig(enriched, "source_ip", "src_ip", ["source", "ip"],
                         "IpAddress", "ClientIP", "RemoteAddress")
    dest_ip       = _dig(enriched, "dest_ip", "destination_ip", ["destination", "ip"],
                         "DestinationIP", "ServerIP")
    affected_user = _dig(enriched, "user", "username", ["source", "user", "name"],
                         "UserPrincipalName", "UserId", "AccountName")
    affected_host = _dig(enriched, "hostname", ["host", "name"],
                         "Computer", "DeviceName", "ComputerName")
    port          = _dig(enriched, "dest_port", "destination_port",
                         ["destination", "port"], "DestinationPort")
    protocol      = _dig(enriched, "protocol", "Protocol")
    action        = _dig(enriched, "event_type", "action", ["event", "action"],
                         "OperationName", "Operation", "Activity")

    e1 = l2["engine_1_anomaly"]
    e2 = l2["engine_2_threat_intel"]
    l2r = l2.get("_layer2_risk", {})

    timeline_entry = {
        "timestamp": ts,
        "event":     log_type + "_event",
        "detail":    f"{action or 'event'} from {source_ip or 'unknown'}"
                     + (f" → {dest_ip}" if dest_ip else "")
                     + (f" port {port}" if port else ""),
    }

    # Layer 1 feature summary for the debug view
    l1_summary = {
        "log_family":            enriched.get("log_family"),
        "classification_conf":   enriched.get("classification_confidence"),
        "temporal_features":     enriched.get("temporal_features"),
        "behavioral_features":   enriched.get("behavioral_features"),
        "statistical_features":  enriched.get("statistical_features"),
        "identity_features":     enriched.get("identity_features"),
        "feature_warnings":      enriched.get("feature_warnings", []),
    }

    # Layer 5 — Playbook selection (dynamic: user/IP/log_type injected)
    playbook = _layer5_playbook(
        action        = action or "",
        tactic        = e2.get("mitre_tactic", ""),
        risk_sev      = l2r.get("severity", "LOW"),
        log_type      = log_type,
        affected_user = affected_user,
        source_ip     = source_ip,
        anomaly_score = e1.get("anomaly_score", 0.0),
    )

    detection = {
        "incident_id":   _make_incident_id(enriched, idx),
        "timestamp":     ts,
        "log_type":      log_type,
        "format":        enriched.get("raw_source") or "uploaded_log",
        "raw_event": {
            "source_ip":      source_ip,
            "destination_ip": dest_ip,
            "affected_user":  affected_user,
            "affected_host":  affected_host,
            "port":           int(port) if port else None,
            "protocol":       protocol,
            "action":         action,
            "timestamp":      ts,
        },
        "engine_1_anomaly":      e1,
        "engine_2_threat_intel": e2,
        "engine_3_correlation": {
            "event_count":     1,
            "attack_timeline": [timeline_entry],
        },
        "layer4_cvss":       l4,
        "ai_analysis":       l3,
        "suggested_playbook": playbook,
        # Extra layer 1 data for the debug view
        "_layer1":      l1_summary,
        "_layer2_risk": l2r,
    }

    return detection


# ── Public entry point ────────────────────────────────────────────────────

def run_pipeline(
    raw_records: list[dict],
    session_id: str = "__default__",
    run_layer3: bool = True,    # now defaults True — safe_runner auto-detects Ollama
) -> list[dict]:
    """
    Run all pipeline layers in-memory on a list of raw records.

    Args:
        raw_records:  list of raw dicts from the parser
        session_id:   session key for Layer 1 behavioral state
        run_layer3:   attempt Layer 3 AI analysis (safe_runner checks Ollama first)

    Returns:
        list of BackendDetection dicts ready for the frontend
    """
    global _pipeline_status
    _pipeline_status["last_run"] = datetime.now(timezone.utc).isoformat()
    _pipeline_status["records_processed"] = len(raw_records)

    # ── Layer 0: Normalise ────────────────────────────────────────────
    _pipeline_status["layer_0"] = "active"
    try:
        from ingestion.log_normalizer import normalize_record as _norm0
        normalized = [_norm0(r) for r in raw_records]
    except Exception as e:
        logger.error("Layer 0 failed: %s", e)
        _pipeline_status["layer_0"] = "error"
        normalized = raw_records
    _pipeline_status["layer_0"] = "done"

    # ── Layer 1: Feature Engineering ─────────────────────────────────
    _pipeline_status["layer_1"] = "active"
    enriched_list: list[dict] = []
    try:
        from layer_1_feature_engineering.feature_orchestrator import run_feature_engineering
        for rec in normalized:
            try:
                enriched_list.append(run_feature_engineering(rec, session_id))
            except Exception as e:
                logger.warning("Layer 1 record error: %s", e)
                enriched_list.append({**rec, "_layer1_error": str(e)})
    except Exception as e:
        logger.error("Layer 1 import failed: %s", e)
        _pipeline_status["layer_1"] = "error"
        enriched_list = normalized
    _pipeline_status["layer_1"] = "done"

    # ── Layers 2–4: Per-record ────────────────────────────────────────
    detections: list[dict] = []

    for idx, enriched in enumerate(enriched_list):
        # Layer 2 — Real detection (mitre_mapper + rules_registry + risk_engine)
        _pipeline_status["layer_2"] = "active"
        try:
            l2 = _layer2_detect(enriched)
        except Exception as e:
            logger.warning("Layer 2 error on record %d: %s", idx, e)
            l2 = {
                "engine_1_anomaly":      {"pyod_score": 0.1, "is_outlier": False,
                                          "ueba_flags": [], "anomaly_score": 0.1,
                                          "anomaly_flagged": False},
                "engine_2_threat_intel": {"ioc_matches": [], "threat_intel_match": False,
                                          "mitre_tactic": "Unknown",
                                          "mitre_technique": "Unknown",
                                          "mitre_technique_name": "Unknown",
                                          "mitre_url": "", "rule_id": "ERROR",
                                          "rule_name": "Error", "rule_confidence": 0.5},
                "_layer2_risk":          {"risk_score": 0.1, "severity": "LOW",
                                          "confidence": 0.5, "components": {}},
                "_layer2_error":         str(e),
            }
        _pipeline_status["layer_2"] = "done"

        # Layer 3 — AI analysis (auto-detects Ollama, graceful fallback)
        _pipeline_status["layer_3"] = "active"
        l3 = None
        if run_layer3:
            partial = _shape_detection(enriched, l2, None, {}, idx)
            l3 = _layer3_ai(partial)
        _pipeline_status["layer_3"] = "done" if run_layer3 else "idle"

        # Layer 4 — Real CVSS scoring with DORA compliance
        _pipeline_status["layer_4"] = "active"
        try:
            # Build a partial detection so Layer 4 can read engine_1/2 + optional AI vector
            partial_for_cvss = {
                "engine_1_anomaly":      l2["engine_1_anomaly"],
                "engine_2_threat_intel": l2["engine_2_threat_intel"],
                "ai_analysis":           l3,
                "is_master":             False,
            }
            l4 = _layer4_cvss(partial_for_cvss)
        except Exception as e:
            logger.warning("Layer 4 error on record %d: %s", idx, e)
            l4 = {"base_score": 0.0, "severity": "LOW",
                  "requires_auto_block": False, "dora_compliance": None,
                  "_layer4_error": str(e)}
        _pipeline_status["layer_4"] = "done"

        detection = _shape_detection(enriched, l2, l3, l4, idx)
        detections.append(detection)

    # ── Layer 5a: Real multi-event correlation (engine_3_correlation) ─
    _pipeline_status["layer_5"] = "active"
    try:
        from layer_2_detection.inmemory_correlator import enrich_all_correlations
        detections = enrich_all_correlations(detections)
    except Exception as e:
        logger.warning("Layer 5 correlation enrichment failed: %s", e)

    # ── Layer 5b: BEC kill-chain detection + master incident collapse ─
    detections = _correlate_incidents(detections)
    _pipeline_status["layer_5"] = "done"
    return detections
