"""
test_layer2_with_enriched.py
============================
Feeds output_enriched.json through the full pipeline (Layers 0-5),
including BEC correlation. Assertions reflect the design intent:
10 raw logs → collapsed into master incidents + ungrouped singles.

Run from backend/ root:
    python test_layer2_with_enriched.py
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main_orchestrator import run_pipeline

ENRICHED_PATH = os.path.join(
    os.path.dirname(__file__),
    "layer_1_feature_engineering",
    "output_enriched.json",
)


def main():
    print(f"\n{'='*70}")
    print("  TuxSOC — Pipeline Smoke Test (with BEC Correlation)")
    print(f"{'='*70}\n")

    with open(ENRICHED_PATH, "r", encoding="utf-8") as f:
        enriched = json.load(f)

    # Build raw records from the enriched JSON (same shape as the frontend sends)
    raw = [{
        'IpAddress':         r.get('IpAddress')         or r.get('ClientIP', ''),
        'UserPrincipalName': r.get('UserPrincipalName') or r.get('UserId', ''),
        'OperationName':     r.get('OperationName')     or r.get('Operation', ''),
        'TimeGenerated':     r.get('@timestamp', ''),
        'RiskState':         r.get('RiskState', ''),
        'RiskLevel':         r.get('RiskLevel', ''),
        'RiskEventTypes':    r.get('RiskEventTypes', ''),
        'Location':          r.get('Location', ''),
        'ClientAppUsed':     r.get('ClientAppUsed', ''),
    } for r in enriched]

    print(f"Loaded {len(raw)} raw records\n")

    detections = run_pipeline(raw, session_id='smoke-test')

    master  = [d for d in detections if d.get('is_master')]
    singles = [d for d in detections if not d.get('is_master')]

    # ── Print summary table ───────────────────────────────────────────
    SEV_COLOR = {
        'CRITICAL': '\033[91m', 'HIGH': '\033[93m',
        'MEDIUM':   '\033[33m', 'LOW':  '\033[92m',
    }
    RESET = '\033[0m'

    print(f"{'#':<4} {'TYPE':<8} {'INCIDENT_ID':<22} {'SEV':<10} "
          f"{'EVENTS':<8} {'USER/IP':<32} {'PLAYBOOK'}")
    print("-" * 110)

    for i, d in enumerate(detections):
        is_m    = d.get('is_master', False)
        iid     = d['incident_id']
        sev     = d.get('layer4_cvss', {}).get('severity', 'LOW')
        events  = d.get('event_count', 1)
        user    = d.get('affected_user') or d.get('raw_event', {}).get('source_ip') or 'unknown'
        pb_id   = d.get('suggested_playbook', {}).get('id', '?')
        kind    = 'MASTER' if is_m else 'single'
        col     = SEV_COLOR.get(sev, '')
        print(f"{i+1:<4} {kind:<8} {iid:<22} {col}{sev:<10}{RESET} "
              f"{events:<8} {user:<32} {pb_id}")

    # ── Assertions ────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("  Verification Assertions")
    print(f"{'='*70}")

    passed = failed = 0

    def check(label: str, cond: bool):
        nonlocal passed, failed
        if cond:
            print(f"  \033[92m✓\033[0m  {label}")
            passed += 1
        else:
            print(f"  \033[91m✗\033[0m  {label}")
            failed += 1

    all_src_ips  = [d.get('raw_event', {}).get('source_ip')    for d in singles]
    all_users    = [d.get('raw_event', {}).get('affected_user') for d in singles]
    all_actions  = [d.get('raw_event', {}).get('action')        for d in singles]
    all_tactics  = [d.get('engine_2_threat_intel', {}).get('mitre_tactic') for d in detections]
    all_sevs     = [d.get('layer4_cvss', {}).get('severity')    for d in detections]

    # Correlation checks (design intent: 10 logs → fewer incidents)
    check("Correlation reduced output below raw input count",
          len(detections) < len(raw))
    check("At least one master incident produced",
          len(master) >= 1)
    check("Master incident has is_master=True",
          all(d.get('is_master') for d in master))
    check("Master incident correlates >1 log",
          all(len(d.get('correlated_log_ids', [])) > 1 for d in master))
    check("Master incident has BEC playbook",
          all(d.get('suggested_playbook', {}).get('id') == 'PB-BEC-001-MASTER' for d in master))
    check("BEC playbook has 4 phases",
          all(len(d['suggested_playbook'].get('phases', [])) == 4 for d in master))
    check("BEC playbook has kill_chain",
          all(len(d['suggested_playbook'].get('kill_chain', [])) >= 1 for d in master))
    check("BEC playbook has dora_flags",
          all(len(d['suggested_playbook'].get('dora_flags', [])) > 0 for d in master))
    check("Master severity is CRITICAL",
          all(d.get('layer4_cvss', {}).get('severity') == 'CRITICAL' for d in master))
    check("finance_mgr@bank.local in a master incident",
          any(d.get('affected_user') == 'finance_mgr@bank.local' for d in master))

    # Individual record quality checks (on singles only)
    check("MITRE tactics mapped (not all Unknown)",
          any(t and t != 'Unknown' for t in all_tactics))
    check("At least one HIGH or CRITICAL detection overall",
          any(s in ('HIGH', 'CRITICAL') for s in all_sevs))

    print(f"\n  {passed} passed, {failed} failed out of {passed+failed} checks")

    # ── Write full JSON output ────────────────────────────────────────
    out_path = os.path.join(os.path.dirname(__file__), "layer2_test_output.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(detections, f, indent=2, default=str)
    print(f"\n  Full output written to: {out_path}")
    print(f"{'='*70}\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
