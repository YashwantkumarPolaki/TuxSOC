"""Quick smoke test for the full pipeline."""
import sys, json
sys.path.insert(0, '.')
from main_orchestrator import run_pipeline, get_pipeline_status

with open('layer_1_feature_engineering/output_enriched.json') as f:
    enriched = json.load(f)

raw = []
for rec in enriched:
    raw.append({
        'IpAddress':         rec.get('IpAddress')         or rec.get('ClientIP') or '',
        'UserPrincipalName': rec.get('UserPrincipalName') or rec.get('UserId')   or '',
        'OperationName':     rec.get('OperationName')     or rec.get('Operation') or '',
        'TimeGenerated':     rec.get('@timestamp')        or '',
        'RiskState':         rec.get('RiskState')         or '',
        'RiskLevel':         rec.get('RiskLevel')         or '',
        'RiskEventTypes':    rec.get('RiskEventTypes')    or '',
        'Location':          rec.get('Location')          or '',
        'ClientAppUsed':     rec.get('ClientAppUsed')     or '',
        'log_id':            rec.get('log_id')            or '',
    })

detections = run_pipeline(raw, session_id='smoke-001')
print(f'Pipeline produced {len(detections)} detections\n')

passed = failed = 0
src_ips = [d['raw_event']['source_ip'] for d in detections]
users   = [d['raw_event']['affected_user'] for d in detections]
actions = [d['raw_event']['action'] for d in detections]
sevs    = [d.get('_layer2_risk', {}).get('severity') for d in detections]
l1_ok   = [bool(d.get('_layer1', {}).get('temporal_features')) for d in detections]
l4_ok   = [bool(d.get('layer4_cvss')) for d in detections]

def check(label, cond):
    global passed, failed
    if cond: passed += 1; print(f'  \033[92m✓\033[0m  {label}')
    else:    failed += 1; print(f'  \033[91m✗\033[0m  {label}')

check('10.0.20.15 in source_ips',              '10.0.20.15'  in src_ips)
check('193.168.0.50 in source_ips',            '193.168.0.50' in src_ips)
check('finance_mgr@bank.local in users',       'finance_mgr@bank.local' in users)
check('No null source_ips',                    all(ip is not None for ip in src_ips))
check('No null users',                         all(u  is not None for u  in users))
check('No null actions',                       all(a  is not None for a  in actions))
check('Layer 1 temporal features present',     all(l1_ok))
check('Layer 4 CVSS present',                  all(l4_ok))
check('At least one HIGH/CRITICAL',            any(s in ('HIGH','CRITICAL') for s in sevs))
check(f'Total = {len(raw)} records',           len(detections) == len(raw))

print(f'\n  {passed} passed, {failed} failed')
print('\nPipeline status:', get_pipeline_status())
