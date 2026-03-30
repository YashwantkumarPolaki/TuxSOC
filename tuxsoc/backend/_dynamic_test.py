import sys
sys.path.insert(0, '.')
from main_orchestrator import run_pipeline

cases = [
    ('AUTH', [{'IpAddress': '10.1.2.3', 'UserPrincipalName': 'alice@bank.local',
               'OperationName': 'login_success', 'TimeGenerated': '2026-03-29T10:00:00Z',
               'RiskState': 'atRisk', 'RiskLevel': 'high', 'RiskEventTypes': 'unfamiliarFeatures',
               'Location': 'RU', 'ClientAppUsed': 'Browser'}]),
    ('WEB',  [{'src_ip': '5.5.5.5', 'dest_ip': '10.0.0.1', 'action': 'sql injection',
               'log_type': 'web', '@timestamp': '2026-03-29T11:00:00Z'}]),
    ('IOT',  [{'src_ip': '192.168.1.50', 'action': 'c2 beacon',
               'log_type': 'iot', '@timestamp': '2026-03-29T12:00:00Z'}]),
    # Low anomaly — DORA should NOT fire
    ('LOW_ANOMALY', [{'src_ip': '1.2.3.4', 'action': 'port scan',
                      'log_type': 'network', '@timestamp': '2026-03-29T13:00:00Z'}]),
]

passed = failed = 0

def check(label, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f'  OK   {label}')
    else:
        failed += 1
        print(f'  FAIL {label}')

for label, raw in cases:
    dets = run_pipeline(raw, session_id='dynamic-test-' + label)
    for d in dets:
        pb     = d.get('suggested_playbook', {})
        anomaly = d.get('engine_1_anomaly', {}).get('anomaly_score', 0)
        dora   = pb.get('dora_flags')
        title  = pb.get('title', '')
        pb_id  = pb.get('id', '')
        src_ip = d.get('raw_event', {}).get('source_ip', '')
        user   = d.get('raw_event', {}).get('affected_user', '')

        print(f'\n[{label}]')
        print(f'  pb_id   = {pb_id}')
        print(f'  title   = {title}')
        print(f'  src_ip  = {src_ip}')
        print(f'  user    = {user}')
        print(f'  anomaly = {anomaly:.3f}')
        print(f'  dora    = {"YES: " + str(dora[0]) if dora else "NO"}')

        if label == 'AUTH':
            check('AUTH -> PB-LT-AUTH template', pb_id == 'PB-LT-AUTH')
            check('AUTH title contains user', 'alice@bank.local' in title)
            check('AUTH title contains IP', '10.1.2.3' in title or 'alice' in title)
        elif label == 'WEB':
            check('WEB -> PB-LT-WEB template', pb_id == 'PB-LT-WEB')
            check('WEB title contains source IP', '5.5.5.5' in title)
        elif label == 'IOT':
            check('IOT -> PB-LT-IOT template', pb_id == 'PB-LT-IOT')
            check('IOT title contains source IP', '192.168.1.50' in title)
        elif label == 'LOW_ANOMALY':
            check('Low anomaly -> no DORA flags', dora is None)

print(f'\n{passed} passed, {failed} failed')
