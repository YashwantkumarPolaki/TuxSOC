import sys, json
sys.path.insert(0, '.')
from main_orchestrator import run_pipeline

with open('layer_1_feature_engineering/output_enriched.json') as f:
    enriched = json.load(f)

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

detections = run_pipeline(raw, session_id='bec-verify')
print(f'\nOutput: {len(detections)} detections from {len(raw)} raw records\n')

passed = failed = 0

def check(label, cond):
    global passed, failed
    if cond: passed += 1; print(f'  \033[92mOK\033[0m  {label}')
    else:    failed += 1; print(f'  \033[91mFAIL\033[0m {label}')

master = [d for d in detections if d.get('is_master')]
singles = [d for d in detections if not d.get('is_master')]

check('At least one master incident produced', len(master) >= 1)
check('Master incident has is_master=True', all(d.get('is_master') for d in master))
check('Master incident has correlated_log_ids', all(len(d.get('correlated_log_ids', [])) > 1 for d in master))
check('Master incident has BEC playbook', all(d.get('suggested_playbook', {}).get('id') == 'PB-BEC-001-MASTER' for d in master))
check('BEC playbook has 4 phases', all(len(d['suggested_playbook'].get('phases', [])) == 4 for d in master))
check('BEC playbook has kill_chain', all(len(d['suggested_playbook'].get('kill_chain', [])) == 4 for d in master))
check('BEC playbook has dora_flags', all(len(d['suggested_playbook'].get('dora_flags', [])) > 0 for d in master))
check('Master severity is CRITICAL', all(d['layer4_cvss']['severity'] == 'CRITICAL' for d in master))
check('finance_mgr@bank.local in master affected_user', any(d.get('affected_user') == 'finance_mgr@bank.local' for d in master))
check('Total output < raw input (correlation happened)', len(detections) < len(raw))

for d in master:
    pb = d['suggested_playbook']
    print(f'\n  Master: {d["incident_id"]}')
    print(f'    user:    {d.get("affected_user")}')
    print(f'    events:  {d.get("event_count")}')
    print(f'    playbook: {pb["id"]}')
    print(f'    phases:  {[p["phase"] for p in pb.get("phases", [])]}')
    print(f'    kill_chain: {[k["stage"] for k in pb.get("kill_chain", [])]}')

print(f'\n  {passed} passed, {failed} failed')
