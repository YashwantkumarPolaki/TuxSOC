import type { Ticket } from '../types/ticket'
import type { PipelineLayer, LivePipelineEvent } from '../types/pipeline'
import type { WatchdogConnection, LogLine } from '../types/watchdog'

export const mockTickets: Ticket[] = [
  {
    id: 'TKT-2024-001',
    severity: 'CRITICAL',
    status: 'OPEN',
    intent: 'Brute force attack on core banking API — credential stuffing via Tor exit nodes',
    attackerIp: '185.220.101.47',
    affectedEntity: 'api-gateway-prod-01',
    cvssScore: 9.8,
    confidence: 97,
    source: 'Syslog',
    createdAt: new Date(Date.now() - 8 * 60000).toISOString(),
    updatedAt: new Date(Date.now() - 2 * 60000).toISOString(),
    actionsTaken: [
      { id: 'a1', action: 'IP flagged by threat intel feed', status: 'completed', timestamp: new Date(Date.now() - 7 * 60000).toISOString(), automated: true },
      { id: 'a2', action: 'Rate limiting applied to /auth endpoint', status: 'completed', timestamp: new Date(Date.now() - 6 * 60000).toISOString(), automated: true },
      { id: 'a3', action: 'SOC analyst notified via PagerDuty', status: 'completed', timestamp: new Date(Date.now() - 5 * 60000).toISOString(), automated: true },
    ],
    recommendations: [
      '🔴 Immediately block IP range 185.220.101.0/24 at perimeter firewall',
      '🔐 Force MFA re-enrollment for all accounts that received auth attempts',
      '📊 Review auth logs for last 24h for lateral movement indicators',
      '🛡️ Enable adaptive authentication for high-risk geographies',
    ],
    playbookId: 'PB-001',
    notes: [],
    mitreTactics: ['Initial Access', 'Credential Access', 'Defense Evasion'],
    aiAnalysis: null,
    suggestedPlaybook: null,
  },
  {
    id: 'TKT-2024-002',
    severity: 'HIGH',
    status: 'IN_PROGRESS',
    intent: 'SQL injection attempt on customer data API — UNION-based extraction pattern',
    attackerIp: '91.108.4.201',
    affectedEntity: 'customer-db-replica-02',
    cvssScore: 8.6,
    confidence: 89,
    source: 'WAF',
    createdAt: new Date(Date.now() - 45 * 60000).toISOString(),
    updatedAt: new Date(Date.now() - 10 * 60000).toISOString(),
    actionsTaken: [
      { id: 'b1', action: 'WAF rule triggered — request blocked', status: 'completed', timestamp: new Date(Date.now() - 44 * 60000).toISOString(), automated: true },
      { id: 'b2', action: 'DB query log analysis initiated', status: 'pending', timestamp: new Date(Date.now() - 20 * 60000).toISOString(), automated: false },
    ],
    recommendations: [
      '🔍 Audit all DB queries from this IP in the last 6 hours',
      '🔒 Parameterize remaining raw SQL queries in customer-api service',
      '📋 Check if any data was exfiltrated before WAF block',
    ],
    playbookId: 'PB-002',
    notes: [{ id: 'n1', analyst: 'J. Chen', content: 'Reviewing DB slow query log — no successful extraction detected yet.', timestamp: new Date(Date.now() - 15 * 60000).toISOString() }],
    mitreTactics: ['Initial Access', 'Collection', 'Exfiltration'],
    aiAnalysis: null,
    suggestedPlaybook: null,
  },
]

export const mockTicketsExtra: Ticket[] = [
  {
    id: 'TKT-2024-003',
    severity: 'CRITICAL',
    status: 'IN_PROGRESS',
    intent: 'Ransomware staging detected — encrypted payload dropper on internal host',
    attackerIp: '10.0.14.88',
    affectedEntity: 'workstation-fin-047',
    cvssScore: 9.1,
    confidence: 94,
    source: 'EDR',
    createdAt: new Date(Date.now() - 120 * 60000).toISOString(),
    updatedAt: new Date(Date.now() - 30 * 60000).toISOString(),
    actionsTaken: [
      { id: 'c1', action: 'Host isolated from network segment', status: 'completed', timestamp: new Date(Date.now() - 115 * 60000).toISOString(), automated: true },
      { id: 'c2', action: 'Memory dump captured for forensics', status: 'completed', timestamp: new Date(Date.now() - 100 * 60000).toISOString(), automated: false },
    ],
    recommendations: [
      '🚨 Escalate to CISO — potential ransomware pre-staging',
      '🔬 Submit payload hash to sandbox analysis',
      '🌐 Check for C2 beaconing on port 443/8443',
    ],
    playbookId: 'PB-003',
    notes: [],
    mitreTactics: ['Execution', 'Persistence', 'Command and Control'],
    aiAnalysis: null,
    suggestedPlaybook: null,
  },
  {
    id: 'TKT-2024-004',
    severity: 'MEDIUM',
    status: 'OPEN',
    intent: 'Anomalous SWIFT transaction pattern — velocity check failure on outbound transfers',
    attackerIp: '172.16.8.12',
    affectedEntity: 'swift-gateway-prod',
    cvssScore: 6.4,
    confidence: 72,
    source: 'SIEM',
    createdAt: new Date(Date.now() - 200 * 60000).toISOString(),
    updatedAt: new Date(Date.now() - 180 * 60000).toISOString(),
    actionsTaken: [
      { id: 'd1', action: 'Transaction velocity alert triggered', status: 'completed', timestamp: new Date(Date.now() - 199 * 60000).toISOString(), automated: true },
    ],
    recommendations: [
      '💰 Review all outbound SWIFT messages in last 2 hours',
      '📞 Contact correspondent bank for confirmation',
      '🔐 Temporarily lower transaction velocity thresholds',
    ],
    playbookId: 'PB-004',
    notes: [],
    mitreTactics: ['Impact', 'Collection'],
    aiAnalysis: null,
    suggestedPlaybook: null,
  },
  {
    id: 'TKT-2024-005',
    severity: 'LOW',
    status: 'RESOLVED',
    intent: 'Port scan from internal subnet — reconnaissance activity on DMZ hosts',
    attackerIp: '10.10.5.33',
    affectedEntity: 'dmz-web-cluster',
    cvssScore: 3.1,
    confidence: 61,
    source: 'Firewall',
    createdAt: new Date(Date.now() - 480 * 60000).toISOString(),
    updatedAt: new Date(Date.now() - 400 * 60000).toISOString(),
    actionsTaken: [
      { id: 'e1', action: 'Source IP logged and monitored', status: 'completed', timestamp: new Date(Date.now() - 479 * 60000).toISOString(), automated: true },
      { id: 'e2', action: 'Confirmed authorized pen test activity', status: 'completed', timestamp: new Date(Date.now() - 420 * 60000).toISOString(), automated: false },
    ],
    recommendations: ['✅ Confirmed authorized — close ticket'],
    notes: [{ id: 'n2', analyst: 'M. Okafor', content: 'Verified with IT Security team — scheduled pen test. Closing.', timestamp: new Date(Date.now() - 410 * 60000).toISOString() }],
    mitreTactics: ['Discovery'],
    aiAnalysis: null,
    suggestedPlaybook: null,
  },
  {
    id: 'TKT-2024-006',
    severity: 'HIGH',
    status: 'OPEN',
    intent: 'Privilege escalation attempt — sudo abuse on Linux banking server',
    attackerIp: '10.0.2.55',
    affectedEntity: 'linux-core-banking-03',
    cvssScore: 7.8,
    confidence: 85,
    source: 'Syslog',
    createdAt: new Date(Date.now() - 25 * 60000).toISOString(),
    updatedAt: new Date(Date.now() - 5 * 60000).toISOString(),
    actionsTaken: [
      { id: 'f1', action: 'Sudo command blocked by PAM policy', status: 'completed', timestamp: new Date(Date.now() - 24 * 60000).toISOString(), automated: true },
    ],
    recommendations: [
      '🔑 Audit sudoers file on all Linux banking servers',
      '👤 Review user account for compromise indicators',
      '📝 Enable auditd for full command logging',
    ],
    notes: [],
    mitreTactics: ['Privilege Escalation', 'Persistence'],
    aiAnalysis: null,
    suggestedPlaybook: null,
  },
  {
    id: 'TKT-2024-007',
    severity: 'MEDIUM',
    status: 'IN_PROGRESS',
    intent: 'Phishing campaign targeting finance team — credential harvesting via spoofed portal',
    attackerIp: '45.33.32.156',
    affectedEntity: 'email-gateway-01',
    cvssScore: 5.9,
    confidence: 78,
    source: 'Email Security',
    createdAt: new Date(Date.now() - 90 * 60000).toISOString(),
    updatedAt: new Date(Date.now() - 45 * 60000).toISOString(),
    actionsTaken: [
      { id: 'g1', action: 'Phishing domain blocked at DNS level', status: 'completed', timestamp: new Date(Date.now() - 88 * 60000).toISOString(), automated: true },
      { id: 'g2', action: 'Affected users notified', status: 'completed', timestamp: new Date(Date.now() - 60 * 60000).toISOString(), automated: false },
    ],
    recommendations: [
      '📧 Send security awareness alert to all finance staff',
      '🔐 Force password reset for users who clicked link',
      '🌐 Submit domain to threat intel sharing platform',
    ],
    notes: [],
    mitreTactics: ['Initial Access', 'Credential Access'],
    aiAnalysis: null,
    suggestedPlaybook: null,
  },
  {
    id: 'TKT-2024-008',
    severity: 'LOW',
    status: 'OPEN',
    intent: 'Failed login spike — 47 failed attempts on ATM management console',
    attackerIp: '203.0.113.42',
    affectedEntity: 'atm-mgmt-console',
    cvssScore: 2.8,
    confidence: 55,
    source: 'CEF',
    createdAt: new Date(Date.now() - 15 * 60000).toISOString(),
    updatedAt: new Date(Date.now() - 15 * 60000).toISOString(),
    actionsTaken: [
      { id: 'h1', action: 'Account lockout policy triggered', status: 'completed', timestamp: new Date(Date.now() - 14 * 60000).toISOString(), automated: true },
    ],
    recommendations: [
      '🔒 Review ATM console access logs',
      '📊 Check if pattern matches known credential spray tools',
    ],
    notes: [],
    mitreTactics: ['Credential Access'],
    aiAnalysis: null,
    suggestedPlaybook: null,
  },
]

export const allMockTickets: Ticket[] = [...mockTickets, ...mockTicketsExtra]

export const mockPipelineLayers: PipelineLayer[] = [
  { id: 'log_sources', name: 'log_sources', displayName: 'LOG SOURCES', status: 'ACTIVE', lastEvent: 'evt_syslog_auth • 1s ago', eventsPerMin: 847, recentLogs: ['Jan 15 10:23:45 fw01 kernel: IN=eth0 OUT= MAC=00:11:22 SRC=185.220.101.47', 'Jan 15 10:23:44 api-gw access: POST /auth 401 185.220.101.47', 'Jan 15 10:23:43 siem: CEF:0|Palo Alto|PAN-OS|10.1|threat|brute-force', 'Jan 15 10:23:42 fw01: DENY TCP 91.108.4.201:54321 -> 10.0.1.5:443', 'Jan 15 10:23:41 auth: Failed password for admin from 185.220.101.47'] },
  { id: 'ingestion', name: 'ingestion', displayName: 'INGESTION', status: 'ACTIVE', lastEvent: 'evt_parse_cef • 2s ago', eventsPerMin: 831, recentLogs: ['[PARSED] syslog → normalized_event{src_ip: 185.220.101.47, action: auth_fail}', '[PARSED] cef → normalized_event{threat: brute_force, severity: high}', '[PARSED] firewall → normalized_event{action: deny, proto: tcp}', '[QUEUED] 14 events pending feature extraction', '[PARSED] json → normalized_event{type: api_access, status: 401}'] },
  { id: 'feature_eng', name: 'feature_eng', displayName: 'FEATURE ENG', status: 'ACTIVE', lastEvent: 'evt_feat_extract • 3s ago', eventsPerMin: 812, recentLogs: ['[FEAT] ip_reputation: 185.220.101.47 → score=0.97 (Tor exit node)', '[FEAT] velocity: 847 auth_fail/min → threshold=50 EXCEEDED', '[FEAT] geo_anomaly: RU→US hop detected in session chain', '[FEAT] time_pattern: off-hours access (02:23 UTC)', '[FEAT] entity_risk: api-gateway-prod-01 → critical_asset=true'] },
  { id: 'detection', name: 'detection', displayName: 'DETECTION', status: 'ACTIVE', lastEvent: 'evt_rule_match • 1s ago', eventsPerMin: 23, recentLogs: ['[MATCH] RULE-047: brute_force_api → confidence=0.97', '[MATCH] RULE-112: tor_exit_node_auth → confidence=0.99', '[MATCH] RULE-089: velocity_threshold_exceeded → confidence=1.0', '[EVAL] 809 events → no match (benign)', '[MATCH] RULE-203: off_hours_critical_asset → confidence=0.82'] },
  { id: 'ai_analysis', name: 'ai_analysis', displayName: 'AI ANALYSIS', status: 'ACTIVE', lastEvent: 'evt_intent_gen • 4s ago', eventsPerMin: 18, recentLogs: ['[AI] intent: "Brute force attack on core banking API via Tor"', '[AI] tactic_map: T1110.004 (Credential Stuffing)', '[AI] kill_chain: Reconnaissance → Initial Access', '[AI] similar_incidents: TKT-2023-847, TKT-2023-901', '[AI] recommended_playbook: PB-001 (Brute Force Response)'] },
  { id: 'cvss', name: 'cvss', displayName: 'CVSS', status: 'ACTIVE', lastEvent: 'evt_score_calc • 2s ago', eventsPerMin: 18, recentLogs: ['[CVSS] AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 CRITICAL', '[CVSS] temporal: exploit_maturity=functional → adjusted=9.6', '[CVSS] env: critical_asset_modifier → final=9.8', '[CVSS] confidence_score: 0.97 → HIGH', '[CVSS] priority_rank: P1 (immediate response required)'] },
  { id: 'response', name: 'response', displayName: 'RESPONSE', status: 'ACTIVE', lastEvent: 'evt_action_taken • 1s ago', eventsPerMin: 12, recentLogs: ['[ACTION] rate_limit applied: /auth → 5 req/min from 185.220.101.47', '[ACTION] threat_intel_tag: 185.220.101.47 → malicious', '[ACTION] pagerduty_alert: P1 sent to on-call analyst', '[ACTION] firewall_rule: BLOCK 185.220.101.0/24 staged', '[ACTION] ticket_created: TKT-2024-001 → OPEN'] },
  { id: 'dashboard', name: 'dashboard', displayName: 'DASHBOARD', status: 'ACTIVE', lastEvent: 'evt_ui_update • 0s ago', eventsPerMin: 12, recentLogs: ['[UI] ticket TKT-2024-001 rendered in dashboard', '[UI] KPI counters updated: critical=3, total=8', '[UI] pipeline beam animation triggered', '[UI] toast notification: CRITICAL alert dispatched', '[UI] analyst workspace refreshed'] },
]

export const mockLiveEvents: LivePipelineEvent[] = [
  { layer: 'log_sources', eventId: 'evt_syslog_auth_001', timestamp: new Date().toISOString(), status: 'processing' },
  { layer: 'ingestion', eventId: 'evt_parse_cef_002', timestamp: new Date().toISOString(), status: 'passed' },
  { layer: 'detection', eventId: 'evt_rule_match_003', timestamp: new Date().toISOString(), status: 'flagged' },
]

export const mockTrendData = Array.from({ length: 30 }, (_, i) => {
  const date = new Date()
  date.setDate(date.getDate() - (29 - i))
  return {
    date: date.toISOString().split('T')[0],
    critical: Math.floor(Math.random() * 5) + 1,
    high: Math.floor(Math.random() * 8) + 2,
    medium: Math.floor(Math.random() * 12) + 3,
    low: Math.floor(Math.random() * 6) + 1,
    cvssAvg: parseFloat((Math.random() * 4 + 5).toFixed(1)),
  }
})

export const mockMitreData = [
  { tactic: 'Initial Access', coverage: 87 },
  { tactic: 'Execution', coverage: 72 },
  { tactic: 'Persistence', coverage: 65 },
  { tactic: 'Priv. Escalation', coverage: 78 },
  { tactic: 'Defense Evasion', coverage: 54 },
  { tactic: 'Credential Access', coverage: 91 },
  { tactic: 'Discovery', coverage: 69 },
  { tactic: 'Exfiltration', coverage: 83 },
]

export const mockPlaybooks = [
  {
    id: 'PB-001',
    title: 'Brute Force / Credential Stuffing Response',
    severity: 'CRITICAL' as const,
    createdAt: '2024-01-10T09:00:00Z',
    content: `# PB-001: Brute Force / Credential Stuffing Response

## Severity: CRITICAL | Category: Credential Attack

### Immediate Actions (0-15 min)

1. **Block attacker IP** at perimeter firewall
\`\`\`bash
# Palo Alto PAN-OS
set security policy-rule block-attacker source-address <IP>/32 action deny
commit
\`\`\`

2. **Apply rate limiting** on affected endpoint
\`\`\`nginx
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
limit_req zone=auth burst=10 nodelay;
\`\`\`

3. **Force MFA** for all accounts that received attempts

### Investigation (15-60 min)

- Review auth logs for successful logins from attacker IP
- Check for lateral movement from any compromised accounts
- Correlate with threat intel feeds (VirusTotal, AbuseIPDB)

### Containment

- Block entire /24 subnet if Tor exit node confirmed
- Enable adaptive authentication for high-risk geos
- Notify affected users to change passwords

### Post-Incident

- Update WAF rules with new patterns
- Submit IOCs to threat sharing platform
- Document in incident register
`,
  },
  {
    id: 'PB-002',
    title: 'SQL Injection Detection & Response',
    severity: 'HIGH' as const,
    createdAt: '2024-01-08T14:30:00Z',
    content: `# PB-002: SQL Injection Detection & Response

## Severity: HIGH | Category: Web Application Attack

### Detection Indicators

- UNION-based extraction patterns in query params
- Error-based injection attempts (MySQL, MSSQL syntax)
- Time-based blind injection (SLEEP, WAITFOR)

### Immediate Actions

1. **Verify WAF block** is active
2. **Capture full request** for forensic analysis
3. **Check DB query logs** for successful injections

\`\`\`sql
-- Check for suspicious queries in last hour
SELECT query_text, execution_time, client_addr
FROM pg_stat_activity
WHERE query_text ILIKE '%UNION%SELECT%'
   OR query_text ILIKE '%1=1%'
ORDER BY query_start DESC;
\`\`\`

### Data Exposure Assessment

- Identify tables accessible via injection point
- Check for data exfiltration in network logs
- Review application error logs for stack traces

### Remediation

- Parameterize all raw SQL queries
- Implement input validation at API layer
- Enable query logging for 30 days post-incident
`,
  },
  {
    id: 'PB-003',
    title: 'Ransomware Pre-Staging Response',
    severity: 'CRITICAL' as const,
    createdAt: '2024-01-05T11:00:00Z',
    content: `# PB-003: Ransomware Pre-Staging Response

## Severity: CRITICAL | Category: Malware / Ransomware

### ⚠️ IMMEDIATE ESCALATION REQUIRED

This playbook requires CISO notification within 15 minutes.

### Containment (First 5 minutes)

1. **Isolate affected host** from all network segments
2. **Preserve memory** — do NOT reboot
3. **Capture disk image** before any remediation

\`\`\`bash
# Network isolation via EDR
edr-cli isolate --host workstation-fin-047 --reason "ransomware-staging"

# Memory capture
winpmem_mini_x64.exe memory.raw
\`\`\`

### Threat Analysis

- Submit payload hash to sandbox (Any.run, Cuckoo)
- Check C2 indicators: port 443, 8443, 4444
- Identify patient zero and infection vector

### Recovery

- Restore from last known-good backup
- Verify backup integrity before restoration
- Conduct full AV scan on restored system
`,
  },
  {
    id: 'PB-004',
    title: 'SWIFT Transaction Anomaly Response',
    severity: 'HIGH' as const,
    createdAt: '2024-01-03T08:00:00Z',
    content: `# PB-004: SWIFT Transaction Anomaly Response

## Severity: HIGH | Category: Financial Fraud

### Regulatory Notice

This incident may require reporting to:
- Central Bank within 4 hours
- SWIFT ISAC within 24 hours
- Local financial regulator per jurisdiction

### Immediate Actions

1. **Freeze suspicious transactions** pending review
2. **Contact correspondent bank** via secure channel
3. **Preserve all SWIFT message logs**

### Investigation

- Review all MT103/MT202 messages in anomaly window
- Check operator credentials for compromise
- Verify transaction authorization chain

### Escalation Matrix

| Severity | Escalation | Timeframe |
|----------|-----------|-----------|
| > $1M | CISO + CFO | Immediate |
| > $100K | SOC Manager | 15 min |
| Any | Compliance | 1 hour |
`,
  },
]

export const mockLogLines: LogLine[] = [
  { id: '1', timestamp: new Date(Date.now() - 1000).toISOString(), source: 'fw-01', level: 'ERROR', content: 'DENY TCP 185.220.101.47:54321 -> 10.0.1.5:443 flags:SYN' },
  { id: '2', timestamp: new Date(Date.now() - 2000).toISOString(), source: 'api-gw', level: 'WARN', content: 'POST /api/v2/auth 401 Unauthorized - 847 attempts in 60s from 185.220.101.47' },
  { id: '3', timestamp: new Date(Date.now() - 3000).toISOString(), source: 'siem', level: 'INFO', content: 'CEF:0|Palo Alto|PAN-OS|10.1|threat|brute-force|9|src=185.220.101.47' },
  { id: '4', timestamp: new Date(Date.now() - 4000).toISOString(), source: 'auth', level: 'ERROR', content: 'Failed password for admin from 185.220.101.47 port 54321 ssh2' },
  { id: '5', timestamp: new Date(Date.now() - 5000).toISOString(), source: 'db-02', level: 'WARN', content: 'Slow query detected: SELECT * FROM customers WHERE id=1 UNION SELECT...' },
  { id: '6', timestamp: new Date(Date.now() - 6000).toISOString(), source: 'edr', level: 'ERROR', content: 'Suspicious process: powershell.exe -enc JABjAGwAaQBlAG4AdA... on workstation-fin-047' },
  { id: '7', timestamp: new Date(Date.now() - 7000).toISOString(), source: 'fw-01', level: 'INFO', content: 'ALLOW TCP 10.0.5.12:443 -> 8.8.8.8:443 bytes:1240' },
  { id: '8', timestamp: new Date(Date.now() - 8000).toISOString(), source: 'api-gw', level: 'DEBUG', content: 'Health check /api/health 200 OK latency:2ms' },
]

export const mockWatchdogConnections: WatchdogConnection[] = [
  {
    id: 'wdg-001',
    type: 'file',
    status: 'WATCHING',
    config: { type: 'file', path: '/var/log/banking/auth.log' },
    stats: { filesDetected: 3, lastIngested: 'auth.log.1', eventsPerMin: 124 },
    liveLines: mockLogLines.slice(0, 5),
    createdAt: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'wdg-002',
    type: 'syslog',
    status: 'STOPPED',
    config: { type: 'syslog', port: 514, protocol: 'UDP' },
    stats: { packetsPerSec: 0 },
    liveLines: [],
    createdAt: new Date(Date.now() - 7200000).toISOString(),
  },
]
