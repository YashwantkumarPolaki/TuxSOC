"""
ingestor.py — Universal Format-Agnostic Ingestor
Layer 2.5 Noisy Log Fidelity Engine

Entry point: universal_ingest(file_input: bytes, file_name: str)

Strategy (hybrid attempt loop):
  1. If filename contains '.xlsx' or '.xls' → try Excel first (openpyxl)
  2. If Excel fails (or extension is not Excel) → stream.seek(0) → try CSV
  3. If both fail → return [] so caller can raise 422

Never raises. Never trusts the extension alone.
fillna("N/A") applied immediately after every successful read.
"""

import io
from typing import Any

import pandas as pd

# ── Fuzzy alias map ───────────────────────────────────────────────────────
ALIAS_MAP: dict[str, list[str]] = {
    "ip": [
        "ip", "src_ip", "source_ip", "srcip", "hostaddress", "host_address",
        "remote_addr", "client_ip", "attacker_ip", "dest_ip", "dst_ip",
        "destination_ip", "ipaddress", "ip_address",
    ],
    "user": [
        "user", "username", "account", "login", "actor", "affected_user",
        "uid", "subject", "identity", "logon", "principal",
    ],
    "action": [
        "action", "event", "event_name", "event_type", "activity",
        "description", "message", "msg", "log_message", "detail",
        "command", "cmd", "process", "operation", "commandline",
        "command_line", "process_name",
    ],
    "severity": [
        "severity", "sev", "level", "priority", "risk",
        "threat_level", "alert_level", "criticality", "rating",
    ],
}

# Keywords that force Critical — checked before Ollama is called
CRITICAL_KEYWORDS: frozenset[str] = frozenset({
    "vssadmin", "lsass", "shadows", "mimikatz", "procdump",
    "sekurlsa", "ntds.dit", "wce.exe", "pwdump", "hashdump",
    "pass-the-hash", "pass the hash", "credential dump",
})


# ── Internal helpers ──────────────────────────────────────────────────────

def _fuzzy_find_column(columns: list[str], aliases: list[str]) -> str | None:
    for col in columns:
        normalised = col.lower().replace(" ", "_").replace("-", "_")
        for alias in aliases:
            if alias in normalised:
                return col
    return None


def _build_col_map(columns: list[str]) -> dict[str, str | None]:
    return {
        canonical: _fuzzy_find_column(columns, aliases)
        for canonical, aliases in ALIAS_MAP.items()
    }


def _safe_str(val: Any) -> str:
    if val is None:
        return "N/A"
    if isinstance(val, float) and val != val:   # NaN
        return "N/A"
    s = str(val).strip()
    return s if s else "N/A"


def _has_critical_keyword(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in CRITICAL_KEYWORDS)


def _df_to_events(df: pd.DataFrame) -> list[dict[str, Any]]:
    """
    Convert a DataFrame (already fillna'd) into the canonical event list.
    Each event has: ip, user, action, severity, raw_row, force_critical, original_columns
    """
    # Defensive fill — belt-and-suspenders in case caller forgot
    df = df.fillna("N/A")

    columns  = list(df.columns)
    col_map  = _build_col_map(columns)
    events: list[dict[str, Any]] = []

    for _, row in df.iterrows():
        try:
            ip       = _safe_str(row[col_map["ip"]])       if col_map["ip"]       else "N/A"
            user     = _safe_str(row[col_map["user"]])     if col_map["user"]     else "N/A"
            action   = _safe_str(row[col_map["action"]])   if col_map["action"]   else "N/A"
            severity = _safe_str(row[col_map["severity"]]) if col_map["severity"] else "N/A"

            raw_row = " | ".join(
                f"{c}={_safe_str(row[c])}" for c in columns if c in row.index
            )

            force_critical = (
                _has_critical_keyword(action) or _has_critical_keyword(raw_row)
            )

            events.append({
                "ip":               ip,
                "user":             user,
                "action":           action,
                "severity":         severity,
                "raw_row":          raw_row[:400],
                "force_critical":   force_critical,
                "original_columns": columns,
            })
        except Exception:
            continue   # skip malformed rows silently

    return events


# ── Public entry point ────────────────────────────────────────────────────

def universal_ingest(file_input: bytes, file_name: str) -> list[dict[str, Any]]:
    """
    Parse any uploaded file into a list of canonical event dicts.

    Hybrid attempt loop:
      - If filename hints at Excel (.xlsx/.xls) → try Excel first
      - On any failure → seek(0) → try CSV
      - If both fail → return []

    Args:
        file_input: raw bytes from the uploaded file
        file_name:  original filename (used as a hint, not trusted absolutely)

    Returns:
        list of event dicts with keys:
            ip, user, action, severity, raw_row, force_critical, original_columns
        Returns [] on total failure — never raises.
    """
    if not file_input:
        return []

    name_lower = (file_name or "").lower()
    looks_like_excel = ".xlsx" in name_lower or ".xls" in name_lower

    # Create a single seekable stream — reused across both attempts
    stream = io.BytesIO(file_input)

    df: pd.DataFrame | None = None

    # ── Attempt 1: Excel (only when filename hints at it) ─────────────────
    if looks_like_excel:
        try:
            df = pd.read_excel(stream, engine="openpyxl", dtype=str)
            df = df.fillna("N/A")
        except Exception:
            df = None
            stream.seek(0)   # MUST reset before CSV attempt

    # ── Attempt 2: CSV / auto-delimiter (always tried if Excel failed) ────
    if df is None:
        try:
            stream.seek(0)   # ensure pointer is at start regardless
            df = pd.read_csv(
                stream,
                sep=None,
                engine="python",
                dtype=str,
                on_bad_lines="skip",
                encoding_errors="replace",
            )
            df = df.fillna("N/A")
        except pd.errors.EmptyDataError:
            return []
        except Exception:
            return []

    # ── Guard: empty DataFrame ────────────────────────────────────────────
    if df is None or df.empty:
        return []

    return _df_to_events(df)
