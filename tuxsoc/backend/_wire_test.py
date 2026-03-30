"""
_wire_test.py — Verify all real layer modules are wired and producing live data.
"""
import sys, json
sys.path.insert(0, '.')
from main_orchestrator import run_pipeline

with open('layer_1_feature_engineering/output_enriched.json') as f:
    enriched = json.load(f)

raw = [{'IpAddress': r.get('IpAddress') or r.get('ClientIP',''),
        'UserPrincipalName': r.get('UserPrincipalName') or r.get('UserId',''),
        'OperationName': r.get('OperationName') or r.get('Operation',''),
        'TimeGenerated': r.get('@timestamp',''),
        'RiskState': r.get('RiskState',''), 'RiskLevel': r.get('RiskLevel','')}
       for r in enriched]

dets = run_pipeline(raw, session_id='wire-test', run_layer3=False)
print(f'\nOutput: {len(dets)} detections from {len(raw)} raw records\n')

passed = failed = 0

def check(label, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f'  OK   {label}')
    else:
        failed += 1
        print(f'  FAIL {label}')

all_techniques = [d.get('engine_2_threat_intel', {}).get('mitre_technique') for d in dets]
all_rule_ids   = [d.get('engine_2_threat_intel', {}).get('rule_id') for d in dets]
all_rule_names = [d.get('engine_2_threat_intel', {}).get('rule_name') for d in dets]
all_dora       = [d.get('layer4_cvss', {}).get('dora_compliance') for d in dets]
all_timelines  = [d.get('engine_3_correlation', {}).get('event_count', 0) for d in dets]
masters        = [d for d in dets if d.get('is_master')]

# Layer 2 checks
check('Real MITRE technique IDs (not Unknown)', any(t and t != 'Unknown' for t in all_techniques))
check('Specific technique T1078 present', any('T1078' in (t or '') for t in all_techniques))
check('Real rule_id populated (not FALLBACK)', any(r and r != 'FALLBACK' for r in all_rule_ids))
check('Real rule_name populated', any(n and n != 'Fallback' for n in all_rule_names))

# Layer 4 checks
check('DORA compliance not all null', any(d is not None for d in all_dora))
check('At least one DORA=True for high-risk events', any(d is True for d in all_dora))

# Layer 5 correlation checks
check('Multi-event timelines (event_count > 1)', any(c > 1 for c in all_timelines))
check('Master incident produced', len(masters) >= 1)
check('Correlation reduced output', len(dets) < len(raw))

print()
for d in dets:
    e2 = d.get('engine_2_threat_intel', {})
    l4 = d.get('layer4_cvss', {})
    e3 = d.get('engine_3_correlation', {})
    is_m = d.get('is_master', False)
    kind = 'MASTER' if is_m else 'single'
    print(f'  [{kind}] {d["incident_id"]}')
    print(f'    mitre={e2.get("mitre_technique")}  tactic={e2.get("mitre_tactic")}')
    print(f'    rule={e2.get("rule_id")}  name={e2.get("rule_name")}')
    print(f'    cvss={l4.get("base_score")}  sev={l4.get("severity")}  dora={l4.get("dora_compliance")}')
    print(f'    timeline_events={e3.get("event_count",0)}  correlated_ids={len(e3.get("correlated_ids",[]))}')
    print()

print(f'{passed} passed, {failed} failed')
