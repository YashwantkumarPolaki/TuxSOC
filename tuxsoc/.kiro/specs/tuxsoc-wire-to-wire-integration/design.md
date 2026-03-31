# TuxSOC Wire-to-Wire Integration Bugfix Design

## Overview

The TuxSOC backend pipeline emits a rich `BackendDetection` JSON structure covering Layers 0–5.
Several fields are either not reaching the React frontend correctly, are mapped to the wrong
source, or are silently dropped during the `detectionToTicket` adapter transform. Additionally,
the Playbooks page lists every individual detection instead of surfacing one comprehensive
playbook per active incident, and KPI counters are computed from a filtered subset rather than
the full aggregated detection list.

This design formalises the bug condition, defines the expected correct behaviour, hypothesises
root causes, and specifies the exact changes required in `adapters.ts`, `useBackendData.ts`,
`backend.ts`, and `Playbooks.tsx`. The FastAPI endpoint contract (`/ingest_file` request and
response shape) is **not changed** — all correlation and aggregation logic lives exclusively on
the frontend side.

---

## Glossary

- **Bug_Condition (C)**: The set of inputs or code paths that trigger one of the defects
  described in the bugfix requirements (Req 1.1–1.18).
- **Property (P)**: The desired observable behaviour when the fixed code processes an input
  satisfying C — i.e. what the frontend must produce after the fix.
- **Preservation**: All existing behaviours for inputs that do NOT satisfy C must remain
  byte-for-byte identical after the fix.
- **BackendDetection**: The TypeScript interface in `src/types/backend.ts` that mirrors the
  Python `build_output()` schema from `fastapi_receiver.py`.
- **detectionToTicket**: The adapter function in `src/api/adapters.ts` that maps one
  `BackendDetection` → one `Ticket`.
- **correlateDetections**: The new frontend-only function (in `useBackendData.ts` or a
  dedicated `correlation.ts` module) that groups a batch of `BackendDetection` objects by
  shared `source_ip` / `destination_ip` and elects a master incident.
- **deriveCVSS**: The existing function in `adapters.ts` that computes the CVSS score for a
  ticket. After the fix it must handle the `base_score = 0.0` / `severity = "NONE"` case.
- **deriveSeverity**: The existing function in `adapters.ts` that maps a detection to a
  `Severity` enum member. After the fix it must reject `"NONE"` as an invalid value.
- **master incident**: A synthetic `BackendDetection`-shaped object produced by the frontend
  correlation step that represents the highest-risk event in a correlated batch and carries
  `is_master: true`, `correlated_log_ids`, and `event_count`.
- **parent_incident_id**: A field added to each sub-event `Ticket` that links it back to the
  master incident's `incident_id`.
- **isBugCondition**: Pseudocode predicate used in this document to identify inputs that
  trigger the bug.

---

## Bug Details

### Bug Condition

The bugs manifest across five distinct code paths in the frontend adapter layer and the
Playbooks page. Each path is formalised below.

**Formal Specification — CVSS / Severity path (Req 1.1, 1.2, 1.10):**

```
FUNCTION isBugCondition_CVSS(d: BackendDetection)
  INPUT:  d — a BackendDetection object
  OUTPUT: boolean

  RETURN (d.layer4_cvss.base_score === 0.0 OR d.layer4_cvss.severity === "NONE")
         AND deriveCVSS(d) returns 0.0          // current broken behaviour
         AND deriveSeverity(d) returns "NONE"   // current broken behaviour
END FUNCTION
```

**Formal Specification — Intent / title path (Req 1.4, 1.9):**

```
FUNCTION isBugCondition_Intent(d: BackendDetection)
  INPUT:  d — a BackendDetection object
  OUTPUT: boolean

  RETURN d.ai_analysis.intent IS NULL
         AND d.raw_event.action IS NULL OR d.raw_event.action === "Unknown"
         AND d.raw_event.source_ip IS NULL
         AND deriveIntent(d) returns "Network activity from unknown source"
         // incident_id is never used in the fallback title
END FUNCTION
```

**Formal Specification — Playbooks page grouping (Req 1.6):**

```
FUNCTION isBugCondition_Playbooks(tickets: Ticket[])
  INPUT:  tickets — the full state.tickets array
  OUTPUT: boolean

  RETURN tickets.filter(t => t.suggestedPlaybook !== null).length > 1
         AND Playbooks left panel renders one row per ticket  // not per incident
         AND master incident is not deduplicated from sub-events
END FUNCTION
```

**Formal Specification — KPI drift (Req 1.7):**

```
FUNCTION isBugCondition_KPI(state: BackendState)
  INPUT:  state — the current BackendState
  OUTPUT: boolean

  RETURN state.kpi.totalTickets !== state.tickets.filter(t => t.status !== "RESOLVED").length
         // KPI was cached from last ingest batch, not recomputed from full state
END FUNCTION
```

**Formal Specification — Batch correlation (Req 1.11–1.18):**

```
FUNCTION isBugCondition_Batch(detections: BackendDetection[])
  INPUT:  detections — array returned by /ingest_file
  OUTPUT: boolean

  RETURN detections.length > 1
         AND detections.some(d => d.raw_event.source_ip === detections[0].raw_event.source_ip)
         AND NO master incident exists in detections  // backend did not correlate
         AND frontend does not run correlateDetections()
END FUNCTION
```

### Examples

- **CVSS zero**: Backend returns `layer4_cvss: { base_score: 0.0, severity: "NONE" }` for a
  sub-event. Current `deriveCVSS` returns `0.0`; expected: `anomaly_score * 10 + ioc_bonus`.
- **Severity NONE**: Same detection. Current `deriveSeverity` returns `"NONE"` (not in the
  `Severity` union); expected: falls through to anomaly-score branch → `"MEDIUM"`.
- **Unknown title**: Detection with `ai_analysis: null`, `action: null`, `source_ip: null`.
  Current title: `"Network activity from unknown source"`. Expected: `"Auth Event: INC-9CB0579DEC85"`.
- **Playbooks flood**: 10-log batch produces 10 playbook entries in the left panel. Expected:
  1 master entry + sub-events hidden or grouped.
- **KPI drift**: After navigation, `kpi.totalTickets` shows stale count from last ingest.
  Expected: always equals `state.tickets.filter(t => t.status !== "RESOLVED").length`.
- **Batch title**: Master incident title shows `"Account Compromise — user@corp.com"`. Expected:
  `"CRITICAL Lateral Movement - 10 Events"`.

---

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- When `layer4_cvss.base_score` is a positive number and `layer4_cvss.severity` is a valid
  `Severity` value, `deriveCVSS` and `deriveSeverity` SHALL continue to use the Layer 4 values
  as authoritative (Req 3.1).
- When `ai_analysis.intent` is non-null, `deriveIntent` SHALL continue to return it with
  highest priority (Req 3.2).
- When `suggested_playbook.phases` is populated on a master incident, `PhasedPlaybook` SHALL
  continue to render the phased layout with per-phase colour coding and icons (Req 3.3).
- When `suggested_playbook.kill_chain` is present, `AttackPath` SHALL continue to render the
  kill-chain timeline (Req 3.4).
- When `suggested_playbook.dora_flags` is present, the DORA flags section SHALL continue to
  render (Req 3.5).
- `state.tickets` and `state.rawDetections` SHALL continue to persist in React state without
  being cleared on navigation (Req 3.6).
- Framer Motion animations and Tailwind theme classes SHALL remain unmodified (Req 3.7).
- When `mitre_tactic` is a real tactic name, `deriveMitreTactics` SHALL continue to return it
  as a single-element array (Req 3.8).
- The Auto-Remediation section SHALL continue to render all entries with the green checkmark
  icon (Req 3.9).
- When `threat_intel_match: true`, `buildRecommendations` SHALL continue to append the IOC
  escalation recommendation (Req 3.10).
- Individual log entries SHALL continue to appear in the Tickets Feed, each retaining its own
  raw event data (Req 3.11).
- A single-log (non-batch) JSON SHALL continue to process through the existing single-event
  flow without requiring a correlation step (Req 3.13).
- All batch-aware components SHALL continue to use the existing Deep Stealth colour palette
  and Tailwind theme classes (Req 3.14).

**Scope:**
All inputs that do NOT satisfy any `isBugCondition_*` predicate above must be completely
unaffected by this fix. This includes:
- Detections with valid `base_score > 0` and valid `severity` strings.
- Detections with non-null `ai_analysis.intent`.
- Single-log ingests that produce exactly one detection.
- Master incidents already produced by the backend (`is_master: true` in the response).

---

## Hypothesized Root Cause

1. **`deriveCVSS` does not guard against `base_score === 0.0`**: The current guard is
   `typeof d.layer4_cvss?.base_score === 'number'`, which is `true` for `0.0`. The function
   therefore returns `0.0` instead of falling through to the anomaly-score formula.

2. **`deriveSeverity` does not validate the `severity` string**: The guard checks for
   `CRITICAL | HIGH | MEDIUM | LOW` but only after confirming `d.layer4_cvss?.severity` is
   truthy. `"NONE"` is truthy, so it passes the truthy check and then fails the union check —
   but the function returns it anyway because the `if` block returns early before the
   anomaly-score branch is reached. The fix is to move the union validation inside the guard.

3. **`deriveIntent` fallback does not use `incident_id`**: The final fallback constructs
   `"${logType} activity from ${srcIp}"`. When `source_ip` is null, `srcIp` becomes
   `"unknown source"`. The `incident_id` field is available on every `BackendDetection` but
   is never referenced in the fallback path.

4. **`Playbooks.tsx` does not deduplicate by `incident_id` / `parent_incident_id`**: The
   `sorted` array is built from `state.tickets.filter(t => t.suggestedPlaybook !== null)`,
   which includes every sub-event ticket. There is no grouping step that collapses sub-events
   under their master.

5. **KPI is computed inside `setState` during `ingestFile`**: `kpi.totalTickets` is set to
   `newTickets.filter(t => t.status !== 'RESOLVED').length` where `newTickets` is the current
   batch only. On re-render after navigation the KPI is not recomputed from `state.tickets`.

6. **`attack_timeline` deduplication is absent**: `deriveActions` maps every entry in
   `engine_3_correlation.attack_timeline` directly to an `ActionEntry` without checking for
   duplicate `incident_id + timestamp` pairs. Master incidents aggregate timelines from all
   sub-events, producing repeated rows.

7. **`backend.ts` `log_type` union is incomplete**: The union is
   `'network' | 'endpoint' | 'auth' | 'firewall' | 'iot'`. The backend `_layer5_playbook`
   function also emits `'web'` and `'azure_ad'` / `'office365'` / `'sharepoint'` (mapped to
   the `auth` template). TypeScript flags these as type errors on valid backend responses.

8. **Frontend has no correlation step**: `ingestFile` calls `detections.map(detectionToTicket)`
   directly. When the backend does not produce a master incident (e.g. the batch does not
   match the BEC kill-chain pattern), no frontend grouping occurs. The design requires a
   frontend `correlateDetections()` function that groups by `source_ip` / `destination_ip`
   and elects a master by highest `anomaly_score`.

9. **`ingestFile` issues one `setState` call that replaces tickets atomically** — this is
   already correct. The bug is that the KPI inside that same `setState` is computed from
   `newTickets` (the batch) rather than `[...prev.tickets, ...newTickets]` or the full
   post-correlation array.

10. **`PlaybookViewer` does not render `aiAnalysis.summary`**: The component renders the
    header, kill-chain, phased steps, and auto-remediation, but there is no section for
    `ticket.aiAnalysis?.summary`. The field is correctly mapped by `deriveAiAnalysis` and
    stored on the `Ticket`, but `Playbooks.tsx` never reads it.

---

## Correctness Properties

Property 1: Bug Condition — CVSS Fallback for Zero / NONE Scores

_For any_ `BackendDetection` where `layer4_cvss.base_score === 0.0` OR
`layer4_cvss.severity === "NONE"`, the fixed `deriveCVSS()` function SHALL return
`min(10, anomaly_score * 10 + ioc_bonus)` and the fixed `deriveSeverity()` function SHALL
return a valid `Severity` member derived from `anomaly_score` and `threat_intel_match`,
never returning `"NONE"` or `0.0`.

**Validates: Requirements 2.1, 2.2, 2.9**

Property 2: Bug Condition — Intent Fallback Uses `incident_id`

_For any_ `BackendDetection` where `ai_analysis.intent` is null AND `raw_event.action` is
null/`"Unknown"` AND `raw_event.source_ip` is null, the fixed `deriveIntent()` function SHALL
return a title in the format `"[LogType] Event: [incident_id]"` (e.g.
`"Auth Event: INC-9CB0579DEC85"`), never returning `"Network activity from unknown source"`.

**Validates: Requirements 2.4, 2.8**

Property 3: Bug Condition — Playbooks Page Shows One Entry Per Incident

_For any_ `state.tickets` array containing correlated sub-events that share a
`parent_incident_id`, the fixed `Playbooks` page SHALL display exactly one entry in the left
panel per unique `incident_id` (master or standalone), grouping all sub-events under their
master and not rendering them as separate panel rows.

**Validates: Requirements 2.5, 2.12, 2.16**

Property 4: Bug Condition — KPI Recomputed from Full State

_For any_ render of a component that reads `state.kpi`, the fixed `useBackendData` hook SHALL
compute `totalTickets` and `avgCvss` from the full `state.tickets` array at render time, such
that `kpi.totalTickets === state.tickets.filter(t => t.status !== "RESOLVED").length` is
always true.

**Validates: Requirements 2.6**

Property 5: Bug Condition — Batch Correlation Produces One Master Incident

_For any_ batch of `BackendDetection` objects where two or more share the same
`raw_event.source_ip` OR `raw_event.destination_ip`, the fixed `correlateDetections()`
function SHALL produce exactly one master `Ticket` (with `isMaster: true`) whose title
follows the format `"[Severity] [PrimaryTactic] - [N] Events"`, with all sub-events linked
via `parent_incident_id`.

**Validates: Requirements 2.12, 2.14, 2.15, 2.16, 2.18**

Property 6: Bug Condition — AI Insights Rendered in PlaybookViewer

_For any_ `Ticket` where `aiAnalysis.summary` is non-null, the fixed `PlaybookViewer`
component SHALL render an "AI Insights" section displaying the summary text below the
incident header.

**Validates: Requirements 2.3**

Property 7: Bug Condition — `attack_timeline` Deduplication

_For any_ `BackendDetection` whose `engine_3_correlation.attack_timeline` contains entries
with duplicate `(incident_id, timestamp)` pairs, the fixed `deriveActions()` function SHALL
deduplicate them so that `actionsTaken` contains no repeated rows.

**Validates: Requirements 2.7**

Property 8: Preservation — Valid CVSS / Severity Unchanged

_For any_ `BackendDetection` where `layer4_cvss.base_score > 0` AND `layer4_cvss.severity`
is a valid `Severity` member, the fixed `deriveCVSS()` and `deriveSeverity()` functions SHALL
produce the same result as the original functions, preserving Layer 4 as the authoritative
source.

**Validates: Requirements 3.1**

Property 9: Preservation — Non-Batch Single-Log Flow Unchanged

_For any_ single-element `detections` array returned by `/ingest_file`, the fixed
`ingestFile` handler SHALL produce the same `Ticket` array as the original handler, with no
correlation step applied and no `parent_incident_id` added.

**Validates: Requirements 3.13**

---

## Fix Implementation

### Data Flow

```
FastAPI /ingest_file
  └─ returns IngestFileResponse { detections: BackendDetection[] }
        │
        ▼
useBackendData.ingestFile()
  ├─ 1. correlateDetections(detections)          ← NEW
  │       └─ groups by source_ip / dest_ip
  │       └─ elects master by max anomaly_score
  │       └─ injects parent_incident_id on sub-events
  │       └─ builds batch title on master
  │
  ├─ 2. correlatedDetections.map(detectionToTicket)
  │       └─ deriveSeverity()   ← FIXED (rejects "NONE")
  │       └─ deriveCVSS()       ← FIXED (guards base_score === 0)
  │       └─ deriveIntent()     ← FIXED (uses incident_id fallback)
  │       └─ deriveActions()    ← FIXED (deduplicates timeline)
  │       └─ deriveAiAnalysis() ← unchanged
  │       └─ deriveSuggestedPlaybook() ← unchanged
  │
  ├─ 3. Single atomic setState({ tickets, rawDetections, kpi, ... })
  │       └─ kpi computed from full newTickets array  ← FIXED
  │
  └─ 4. KPI recomputed on every render from state.tickets  ← FIXED

state.tickets
  └─ Playbooks.tsx
        └─ deduplicateByIncident(tickets)          ← NEW
              └─ one panel row per unique incident_id
              └─ PlaybookViewer renders AI Insights ← NEW
```

### Changes Required

#### File: `src/types/backend.ts`

**Change 1 — Extend `log_type` union (Req 2.10):**
```typescript
// Before
log_type: 'network' | 'endpoint' | 'auth' | 'firewall' | 'iot'

// After
log_type: 'network' | 'endpoint' | 'auth' | 'firewall' | 'iot' | 'web' | 'azure_ad' | 'office365' | 'sharepoint'
```

**Change 2 — Add `parent_incident_id` to `BackendDetection`:**
```typescript
parent_incident_id?: string   // set by frontend correlateDetections(), not backend
```

#### File: `src/types/ticket.ts`

**Change 3 — Add `parent_incident_id` to `Ticket`:**
```typescript
parentIncidentId?: string   // links sub-event to its master incident
```

#### File: `src/api/adapters.ts`

**Change 4 — Fix `deriveCVSS` (Req 2.1):**
```typescript
function deriveCVSS(d: BackendDetection): number {
  // Only use Layer 4 score when it is a meaningful positive value
  if (typeof d.layer4_cvss?.base_score === 'number'
      && d.layer4_cvss.base_score > 0
      && d.layer4_cvss.severity !== 'NONE') {
    return parseFloat(Math.min(10, d.layer4_cvss.base_score).toFixed(1))
  }
  // Fallback: anomaly_score formula
  const base = d.engine_1_anomaly.anomaly_score * 10
  const iocBonus = d.engine_2_threat_intel.threat_intel_match ? 0.5 : 0
  return Math.min(10, parseFloat((base + iocBonus).toFixed(1)))
}
```

**Change 5 — Fix `deriveSeverity` (Req 2.2, 2.9):**
```typescript
function deriveSeverity(d: BackendDetection): Severity {
  if (d.layer4_cvss?.severity) {
    const s = d.layer4_cvss.severity.toUpperCase()
    // Explicitly reject "NONE" — fall through to anomaly-score branch
    if (s === 'CRITICAL' || s === 'HIGH' || s === 'MEDIUM' || s === 'LOW') return s as Severity
  }
  // anomaly-score branch (unchanged)
  const score = d.engine_1_anomaly.anomaly_score
  const action = (d.raw_event.action ?? '').toLowerCase()
  const iocHit = d.engine_2_threat_intel.threat_intel_match
  if (score >= 0.85 || iocHit || /brute.?force|credential.stuff|ransomware|c2|botnet/.test(action))
    return 'CRITICAL'
  if (score >= 0.70 || /lateral.mov|pass.the.hash|exfil|spray|sweep/.test(action))
    return 'HIGH'
  if (score >= 0.55 || d.engine_1_anomaly.ueba_flags.length > 0)
    return 'MEDIUM'
  return 'LOW'
}
```

**Change 6 — Fix `deriveIntent` fallback (Req 2.4, 2.8):**
```typescript
// Replace the final fallback line:
// Before: return `${logType} activity from ${srcIp}`
// After:
const logType = d.log_type.charAt(0).toUpperCase() + d.log_type.slice(1)
return `${logType} Event: ${d.incident_id}`
```

**Change 7 — Fix `deriveActions` deduplication (Req 2.7):**
```typescript
function deriveActions(d: BackendDetection): ActionEntry[] {
  const seen = new Set<string>()
  return d.engine_3_correlation.attack_timeline
    .filter(entry => {
      const key = `${entry.timestamp}::${entry.detail}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    .map((entry, i) => ({
      id: `${d.incident_id}-act-${i}`,
      action: entry.detail,
      status: 'completed' as const,
      timestamp: entry.timestamp,
      automated: true,
    }))
}
```

**Change 8 — Pass `parent_incident_id` through `detectionToTicket`:**
```typescript
// Add to the returned Ticket object:
parentIncidentId: d.parent_incident_id,
```

#### File: `src/api/correlation.ts` (NEW FILE)

This module implements the frontend correlation step. It must not call the backend.

**`correlateDetections(detections: BackendDetection[]): BackendDetection[]`**

Algorithm:

```
FUNCTION correlateDetections(detections)
  INPUT:  detections — raw array from /ingest_file
  OUTPUT: correlated array with master incidents injected

  // Step 1: Pass through any backend-produced master incidents unchanged
  backendMasters = detections.filter(d => d.is_master === true)
  nonMasters     = detections.filter(d => d.is_master !== true)

  // Step 2: Group non-master detections by source_ip, then by destination_ip
  groups = Map<string, BackendDetection[]>
  FOR EACH d IN nonMasters:
    key = d.raw_event.source_ip ?? d.raw_event.destination_ip ?? d.incident_id
    groups[key].push(d)

  // Step 3: For groups with > 1 member, elect a master
  result = [...backendMasters]
  FOR EACH (key, group) IN groups:
    IF group.length === 1:
      result.push(group[0])   // single event — no correlation needed
    ELSE:
      master = group with max(engine_1_anomaly.anomaly_score)
      masterDetection = buildFrontendMaster(master, group)
      subEvents = group.map(d => { ...d, parent_incident_id: masterDetection.incident_id })
      result.push(masterDetection, ...subEvents)

  RETURN result
END FUNCTION
```

**`buildFrontendMaster(anchor, group): BackendDetection`**

```
FUNCTION buildFrontendMaster(anchor, group)
  severity    = deriveSeverity(anchor)   // uses fixed deriveSeverity
  primaryTactic = anchor.engine_2_threat_intel.mitre_tactic
  batchCount  = group.length
  sourceIPs   = unique(group.map(d => d.raw_event.source_ip).filter(Boolean))

  // Batch-aware title (Req 2.18)
  batchTitle  = `${severity} ${primaryTactic} - ${batchCount} Events`

  // CVSS consolidation (Req 2.14): max base_score across batch, fallback formula
  consolidatedCVSS = deriveCVSS_batch(group)

  // Playbook: use anchor's playbook but inject batch-aware steps (Req 2.15)
  batchPlaybook = buildBatchPlaybook(anchor.suggested_playbook, group, sourceIPs)

  RETURN {
    ...anchor,
    is_master:           true,
    correlated_log_ids:  group.map(d => d.incident_id),
    event_count:         batchCount,
    affected_user:       anchor.raw_event.affected_user ?? anchor.raw_event.destination_ip,
    suggested_playbook:  batchPlaybook,
    // Override title via ai_analysis.intent so deriveIntent() picks it up
    ai_analysis: {
      ...anchor.ai_analysis,
      intent: batchTitle,
    },
  }
END FUNCTION
```

**`deriveCVSS_batch(group): number` — Layer 4 CVSS consolidation (Req 2.14):**

```
FUNCTION deriveCVSS_batch(group)
  // Collect all valid base_scores from the batch
  validScores = group
    .filter(d => d.layer4_cvss?.base_score > 0 AND d.layer4_cvss?.severity !== "NONE")
    .map(d => d.layer4_cvss.base_score)

  IF validScores.length > 0:
    RETURN min(10, max(validScores))   // highest authoritative score wins

  // Fallback: anomaly-score formula applied to the anchor (highest anomaly_score)
  anchor = group with max(engine_1_anomaly.anomaly_score)
  base   = anchor.engine_1_anomaly.anomaly_score * 10
  bonus  = anchor.engine_2_threat_intel.threat_intel_match ? 0.5 : 0
  RETURN min(10, base + bonus)
END FUNCTION
```

**`buildBatchPlaybook(basePb, group, sourceIPs): SuggestedPlaybook` — batch-aware steps (Req 2.15):**

```
FUNCTION buildBatchPlaybook(basePb, group, sourceIPs)
  IF basePb IS NULL: RETURN NULL

  batchCount = group.length
  ipList     = sourceIPs.join(", ")

  // Prepend a batch-context step to the existing steps array
  batchStep  = `Block IPs [${ipList}] — observed across ${batchCount} correlated events in this batch`
  batchSteps = [batchStep, ...basePb.steps]

  RETURN { ...basePb, steps: batchSteps }
END FUNCTION
```

#### File: `src/hooks/useBackendData.ts`

**Change 9 — Call `correlateDetections` before mapping to tickets (Req 2.12, 2.16):**
```typescript
// Inside ingestFile, replace:
//   const newTickets = detections.map(detectionToTicket)
// With:
import { correlateDetections } from '../api/correlation'
const correlated = correlateDetections(detections)
const newTickets = correlated.map(detectionToTicket)
```

**Change 10 — Compute KPI from full `newTickets` (Req 2.6):**

The existing `setState` already computes KPI from `newTickets` (the full correlated batch).
The fix is to ensure `newTickets` is the post-correlation array (Change 9 above), not the
raw `detections` array. No additional change is needed beyond Change 9.

For the navigation-drift case: expose a `recomputeKpi` selector or compute KPI inline in
the component that reads it, deriving from `state.tickets` directly:

```typescript
// In any component that displays KPI values:
const totalTickets = state.tickets.filter(t => t.status !== 'RESOLVED').length
const avgCvss = state.tickets.length > 0
  ? state.tickets.reduce((s, t) => s + t.cvssScore, 0) / state.tickets.length
  : 0
```

#### File: `src/pages/Playbooks.tsx`

**Change 11 — Deduplicate left panel by incident (Req 2.5):**

```typescript
// Replace the current `sorted` derivation with:
FUNCTION deduplicateByIncident(tickets: Ticket[]): Ticket[]
  // Show master incidents and standalone tickets only
  // Sub-events (those with parentIncidentId) are hidden from the panel
  masterIds = new Set(tickets.filter(t => t.isMaster).map(t => t.id))
  return tickets.filter(t =>
    t.isMaster ||
    (!t.parentIncidentId) ||
    (!masterIds.has(t.parentIncidentId))  // orphaned sub-event — show it
  )
END FUNCTION
```

**Change 12 — Render AI Insights in `PlaybookViewer` (Req 2.3):**

Insert an "AI Insights" section between the header card and the two-column layout:

```tsx
{ticket.aiAnalysis?.summary && (
  <div className="rounded-xl p-4"
    style={{ backgroundColor: 'rgba(17,24,39,0.9)', border: '1px solid rgba(59,130,246,0.2)' }}>
    <div className="flex items-center gap-2 mb-2">
      <AlertCircle size={11} style={{ color: '#3B82F6' }} />
      <span className="text-[9px] font-mono font-bold tracking-widest uppercase"
        style={{ color: '#3B82F6' }}>AI Insights</span>
    </div>
    <p className="text-[11px] font-mono leading-relaxed" style={{ color: '#94a3b8' }}>
      {ticket.aiAnalysis.summary}
    </p>
  </div>
)}
```

---

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that
demonstrate each bug on the unfixed code, then verify the fix works correctly and preserves
existing behaviour.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate each bug BEFORE implementing the fix.
Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write unit tests that feed crafted `BackendDetection` fixtures into the
current (unfixed) adapter functions and assert the broken output. Run these on the UNFIXED
code to observe failures and confirm root causes.

**Test Cases**:
1. **CVSS zero passthrough** (will fail on unfixed code): Feed `{ layer4_cvss: { base_score: 0.0, severity: "NONE" } }` to `deriveCVSS` — assert result is NOT `0.0`.
2. **Severity NONE passthrough** (will fail on unfixed code): Feed same fixture to `deriveSeverity` — assert result is not `"NONE"`.
3. **Intent unknown source** (will fail on unfixed code): Feed `{ ai_analysis: null, raw_event: { action: null, source_ip: null } }` to `deriveIntent` — assert result contains `incident_id`.
4. **Timeline duplicates** (will fail on unfixed code): Feed a detection with two identical `attack_timeline` entries — assert `deriveActions` returns length 1.
5. **Batch no correlation** (will fail on unfixed code): Feed 3 detections sharing `source_ip` to `ingestFile` mock — assert no master ticket is produced.

**Expected Counterexamples**:
- `deriveCVSS` returns `0.0` for zero `base_score` inputs.
- `deriveSeverity` returns `"NONE"` for `severity: "NONE"` inputs.
- `deriveIntent` returns `"Network activity from unknown source"` for null action + null IP.
- `deriveActions` returns duplicate `ActionEntry` rows for duplicate timeline entries.
- No master ticket is produced for a multi-IP batch without backend correlation.

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed functions
produce the expected behaviour.

**Pseudocode:**
```
FOR ALL d WHERE isBugCondition_CVSS(d) DO
  result := deriveCVSS_fixed(d)
  ASSERT result > 0.0
  ASSERT result === anomaly_score * 10 + ioc_bonus (capped at 10)
END FOR

FOR ALL d WHERE isBugCondition_Intent(d) DO
  result := deriveIntent_fixed(d)
  ASSERT result.includes(d.incident_id)
  ASSERT NOT result.includes("unknown source")
END FOR

FOR ALL batch WHERE isBugCondition_Batch(batch) DO
  result := correlateDetections_fixed(batch)
  masters := result.filter(d => d.is_master)
  ASSERT masters.length === 1
  ASSERT masters[0].ai_analysis.intent matches /^\w+ \w+ - \d+ Events$/
  ASSERT masters[0].layer4_cvss.base_score === max(batch.map(d => d.layer4_cvss.base_score))
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed
functions produce the same result as the original functions.

**Pseudocode:**
```
FOR ALL d WHERE NOT isBugCondition_CVSS(d) DO
  ASSERT deriveCVSS_original(d) === deriveCVSS_fixed(d)
END FOR

FOR ALL d WHERE NOT isBugCondition_Intent(d) DO
  ASSERT deriveIntent_original(d) === deriveIntent_fixed(d)
END FOR

FOR ALL batch WHERE batch.length === 1 DO
  ASSERT ingestFile_original(batch) === ingestFile_fixed(batch)
  // No correlation step applied, no parent_incident_id added
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain.
- It catches edge cases that manual unit tests might miss.
- It provides strong guarantees that behaviour is unchanged for all non-buggy inputs.

**Test Plan**: Observe behaviour on UNFIXED code first for valid CVSS inputs, valid intent
inputs, and single-log batches, then write property-based tests capturing that behaviour.

**Test Cases**:
1. **Valid CVSS preservation**: Generate random `base_score > 0` with valid `severity` — verify `deriveCVSS` returns the same value before and after fix.
2. **AI intent preservation**: Generate detections with non-null `ai_analysis.intent` — verify `deriveIntent` returns the intent string unchanged.
3. **Single-log preservation**: Feed single-element arrays to `ingestFile` — verify ticket count is 1 and no `parentIncidentId` is set.
4. **Master incident preservation**: Feed a detection with `is_master: true` from the backend — verify it passes through `correlateDetections` unchanged.
5. **Playbook phases preservation**: Feed a master ticket with `phases` populated — verify `PhasedPlaybook` still renders the phased layout.

### Unit Tests

- `deriveCVSS`: zero `base_score`, `"NONE"` severity, valid positive score, missing `layer4_cvss`.
- `deriveSeverity`: `"NONE"` input, `"CRITICAL"` input, missing `layer4_cvss`, anomaly-score thresholds.
- `deriveIntent`: null action + null IP (uses `incident_id`), non-null AI intent (highest priority), real action string.
- `deriveActions`: duplicate timeline entries (deduplication), empty timeline, single entry.
- `correlateDetections`: single detection (no-op), two detections same `source_ip` (produces master), two detections different IPs (no grouping), backend-produced master (pass-through).
- `deriveCVSS_batch`: all zero scores (fallback formula), mixed valid/zero (max valid wins), all valid (max wins).
- `buildBatchPlaybook`: null base playbook (returns null), valid playbook (prepends batch step with IP list and count).

### Property-Based Tests

- Generate random `BackendDetection` objects with `base_score` drawn from `[0.0, 0.1, ..., 10.0]` — verify `deriveCVSS` never returns `0.0` when `base_score === 0.0`.
- Generate random batches of 1–20 detections with random `source_ip` values — verify `correlateDetections` produces at most one master per unique IP, and total output length equals input length + number of masters injected.
- Generate random `Ticket` arrays with mixed `isMaster` / `parentIncidentId` values — verify `deduplicateByIncident` never shows a sub-event whose master is also in the panel.
- Generate random `attack_timeline` arrays with random duplicate rates — verify `deriveActions` output length ≤ input length and contains no duplicate `(timestamp, action)` pairs.

### Integration Tests

- Upload a 10-log JSON batch where all logs share the same `source_ip` — verify the Playbooks page shows exactly 1 master entry in the left panel with title matching `"[SEV] [Tactic] - 10 Events"`.
- Upload a 10-log JSON batch where logs have 3 distinct `source_ip` values — verify 3 master entries in the Playbooks panel (one per IP group).
- Upload a single-log JSON — verify the Playbooks panel shows 1 entry, no `MASTER` badge, no `parentIncidentId` on the ticket.
- Navigate away from Playbooks to Dashboard and back — verify `kpi.totalTickets` equals the number of non-RESOLVED tickets in `state.tickets`.
- Upload a batch where the backend returns `is_master: true` on one detection — verify `correlateDetections` does not create a second master for the same group.
- Verify the AI Insights section appears in `PlaybookViewer` when `aiAnalysis.summary` is non-null, and is absent when it is null.
