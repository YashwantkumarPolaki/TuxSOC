"""
statistical_orchestrator.py — Engine 3: Statistical Feature Extraction
=======================================================================
Computes frequency analysis and spike detection features.
Called by feature_orchestrator.run_feature_engineering().
"""
from __future__ import annotations
import math
import re

_RISK_KEYWORDS = [
    r"ransomware", r"mimikatz", r"lsass", r"vssadmin", r"procdump",
    r"powershell.*bypass", r"invoke-expression", r"encodedcommand",
    r"union select", r"1=1", r"exec\(", r"cmd\.exe", r"bash -i",
    r"wget.*http", r"curl.*http", r"nc -e", r"netcat",
    r"new-inboxrule", r"forwardto", r"filedownloaded",
    r"mass_file_modification", r"shadow copy",
]
_RISK_RE = re.compile("|".join(_RISK_KEYWORDS), re.IGNORECASE)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_statistical_features(record: dict, action: str = "") -> dict:
    """
    Returns the statistical_features block for a single record.

    Fields:
      action_entropy    — Shannon entropy of the action string
      risk_keyword_hits — count of high-risk keywords found
      risk_keywords     — deduplicated list of matched keywords
    """
    if not action:
        action = record.get("_l1_action") or record.get("OperationName") or ""

    entropy = round(_shannon_entropy(action), 4)
    matches = _RISK_RE.findall(action)
    keywords = list(set(k.lower() for k in matches))

    return {
        "action_entropy":    entropy,
        "risk_keyword_hits": len(matches),
        "risk_keywords":     keywords,
    }
