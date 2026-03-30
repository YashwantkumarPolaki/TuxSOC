"""
analyzer.py — Ollama-Powered SOC Fidelity Analyzer
Layer 2.5 Noisy Log Fidelity Engine

Uses raw HTTP to Ollama (localhost:11434) with temperature=0.

System prompt explicitly instructs the model to:
  - Ignore the original_severity column
  - Re-evaluate ONLY from the action/command string
  - Apply DORA operational resilience severity standards
  - Return strict JSON with the 4 required fields
"""

import json
import re
import asyncio
import httpx
from typing import Any

# ── Ollama config ─────────────────────────────────────────────────────────
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL    = "llama3.2"
OLLAMA_TIMEOUT  = 90    # seconds — per-request cap; reduced to avoid cascade timeouts

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
FALLBACK_SEVERITY = "Medium"

# ── DORA-aligned system prompt ────────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are a Barclays SOC Analyst operating under DORA (EU Digital Operational Resilience Act) standards.

You are being given security logs with WRONG or MISSING severity labels.

YOUR RULES:
1. IGNORE the 'original_severity' field completely — it is unreliable.
2. Look ONLY at the 'action' / 'command' field to determine the real threat.
3. Apply DORA operational resilience severity standards:
   - Critical: Active exploitation, credential dumping (lsass, mimikatz, vssadmin, shadows),
               ransomware staging, C2 beaconing, data exfiltration to external IPs.
   - High:     Brute force, lateral movement, privilege escalation, suspicious process chains,
               off-hours admin access, pass-the-hash.
   - Medium:   Reconnaissance, unusual protocols, failed logins below threshold,
               unconfirmed anomalies.
   - Low:      Authorized scheduled jobs, known service accounts, benign internal traffic.
4. If the action contains ANY of these strings, revised_severity MUST be 'Critical':
   vssadmin, lsass, shadows, mimikatz, procdump, sekurlsa, ntds.dit, pwdump, hashdump
5. Return PURE JSON only. No markdown, no code fences, no explanation outside the JSON.
6. Start your response with '{' and end with '}'.
"""

# ── Required output keys ──────────────────────────────────────────────────
REQUIRED_KEYS = {"event_name", "explanation", "recommended_actions", "revised_severity"}


# ── JSON extraction (4-strategy fallback) ────────────────────────────────

def _try_direct(text: str) -> dict | None:
    try:
        return json.loads(text.strip())
    except Exception:
        return None


def _try_extract_block(text: str) -> dict | None:
    try:
        start = text.find("{")
        end   = text.rfind("}")
        if start == -1 or end <= start:
            return None
        return json.loads(text[start:end + 1])
    except Exception:
        return None


def _try_clean(text: str) -> dict | None:
    try:
        cleaned = re.sub(r"```json\s*", "", text)
        cleaned = re.sub(r"```\s*",     "", cleaned)
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        start = cleaned.find("{")
        end   = cleaned.rfind("}")
        if start == -1 or end <= start:
            return None
        return json.loads(cleaned[start:end + 1])
    except Exception:
        return None


def _parse_llm_output(text: str) -> dict | None:
    for fn in (_try_direct, _try_extract_block, _try_clean):
        result = fn(text)
        if result and isinstance(result, dict):
            return result
    return None


def _normalise_severity(raw: str) -> str:
    if not raw:
        return FALLBACK_SEVERITY
    cap = raw.strip().capitalize()
    if cap in VALID_SEVERITIES:
        return cap
    lower = raw.lower()
    if "crit" in lower: return "Critical"
    if "high" in lower: return "High"
    if "med"  in lower: return "Medium"
    if "low"  in lower: return "Low"
    return FALLBACK_SEVERITY


def _fallback_result(event: dict[str, Any], reason: str) -> dict[str, Any]:
    severity = "Critical" if event.get("force_critical") else FALLBACK_SEVERITY
    return {
        "event_name":          (event.get("action") or "Unknown Activity")[:80],
        "explanation":         f"Ollama unavailable ({reason}). Severity derived from keyword analysis only.",
        "recommended_actions": [
            "Review the raw log entry manually",
            "Correlate with SIEM for additional context",
            "Escalate to Tier-2 analyst if action string is suspicious",
        ],
        "revised_severity":    severity,
        "_ollama_used":        False,
    }


# ── Per-event prompt ──────────────────────────────────────────────────────

def _build_prompt(event: dict[str, Any]) -> str:
    force_note = (
        "\n⚠️  CRITICAL KEYWORD DETECTED — revised_severity MUST be 'Critical'."
        if event.get("force_critical") else ""
    )
    return f"""{_SYSTEM_PROMPT}

### LOG EVENT:
- Source IP:                {event.get('ip', 'N/A')}
- User / Account:           {event.get('user', 'N/A')}
- Action / Command:         {event.get('action', 'N/A')}
- Original Severity (IGNORE): {event.get('severity', 'N/A')}
- Raw Row Context:          {(event.get('raw_row') or '')[:300]}{force_note}

### REQUIRED JSON OUTPUT — exactly these 4 keys:
{{
    "event_name":          "Standardised threat name (e.g., Credential Dumping via LSASS)",
    "explanation":         "1-2 sentences: why this severity was assigned under DORA standards.",
    "recommended_actions": [
        "Specific tactical step 1",
        "Specific tactical step 2",
        "Specific tactical step 3",
        "Specific tactical step 4"
    ],
    "revised_severity":    "Critical | High | Medium | Low"
}}"""


# ── Public API ────────────────────────────────────────────────────────────

async def analyse_event(event: dict[str, Any]) -> dict[str, Any]:
    """
    Analyse a single normalised event using async httpx — never blocks the event loop.
    Short-circuits to Critical immediately if force_critical is set.
    Falls back gracefully when Ollama is unreachable.
    """
    # Fast path — critical keyword detected, no LLM needed
    if event.get("force_critical"):
        action = event.get("action", "Unknown activity")
        return {
            "event_name":          f"Critical Threat: {action[:60]}",
            "explanation":         (
                f"Critical keyword detected in action string: '{action[:120]}'. "
                "Under DORA standards this pattern indicates credential dumping or "
                "ransomware staging — immediate escalation required."
            ),
            "recommended_actions": [
                "Immediately isolate the affected host from all network segments",
                "Capture a full memory dump before any remediation steps",
                "Escalate to CISO and Incident Response team within 15 minutes",
                "Submit process hash to sandbox (Any.run / Cuckoo) for analysis",
            ],
            "revised_severity":    "Critical",
            "_ollama_used":        False,
            "_force_critical":     True,
        }

    prompt = _build_prompt(event)

    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            response = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model":   OLLAMA_MODEL,
                    "prompt":  prompt,
                    "stream":  False,
                    "options": {"temperature": 0},
                },
            )
        # Capture the body before raising so we can log it on error
        if not response.is_success:
            body_preview = response.text[:300]
            return _fallback_result(
                event,
                f"{response.status_code} {response.reason_phrase} — body: {body_preview}",
            )
        raw_text = response.json().get("response", "")
    except httpx.ConnectError:
        return _fallback_result(event, "Ollama not running on localhost:11434")
    except httpx.TimeoutException:
        return _fallback_result(event, "Ollama request timed out")
    except Exception as e:
        return _fallback_result(event, str(e))

    parsed = _parse_llm_output(raw_text)
    if not parsed:
        return _fallback_result(event, f"JSON parse failed. Raw: {raw_text[:120]}")

    actions = parsed.get("recommended_actions")
    if not isinstance(actions, list) or len(actions) == 0:
        actions = [
            "Review event manually",
            "Correlate with SIEM",
            "Escalate if suspicious",
        ]

    return {
        "event_name":          str(parsed.get("event_name", event.get("action", "Unknown"))[:120]),
        "explanation":         str(parsed.get("explanation", "No explanation provided.")),
        "recommended_actions": [str(a) for a in actions],
        "revised_severity":    _normalise_severity(str(parsed.get("revised_severity", ""))),
        "_ollama_used":        True,
    }


async def analyse_batch(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Process events concurrently within the batch — non-blocking, async-safe."""
    return list(await asyncio.gather(*[analyse_event(e) for e in events]))
