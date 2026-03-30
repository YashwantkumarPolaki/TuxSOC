"""
shared/config.py
----------------
Constants shared across layer_4_cvss engines.
"""

# CVSS v3.1 severity thresholds (NVD standard)
SEVERITY_THRESHOLDS = {
    "CRITICAL": 9.0,
    "HIGH":     7.0,
    "MEDIUM":   4.0,
    "LOW":      0.1,
    "NONE":     0.0,
}

# Number of CIS violations required to escalate severity by one level
CIS_ESCALATION_THRESHOLD = 3

# CVSS metric severity ordering (worst → best) for CIS penalty escalation
CVSS_METRIC_SEVERITY_ORDER = {
    "AV": ["P", "L", "A", "N"],   # Physical < Local < Adjacent < Network
    "AC": ["H", "L"],              # High < Low
    "PR": ["H", "L", "N"],         # High < Low < None
    "UI": ["R", "N"],              # Required < None
    "S":  ["U", "C"],              # Unchanged < Changed
    "C":  ["N", "L", "H"],         # None < Low < High
    "I":  ["N", "L", "H"],
    "A":  ["N", "L", "H"],
}
