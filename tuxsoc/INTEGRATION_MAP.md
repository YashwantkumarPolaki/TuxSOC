# TuxSOC — Integration Map
**Source of Truth | Last audited: 2026-03-28**

This document is the authoritative reference for the current state of the TuxSOC frontend-backend integration. It covers every page, every backend file, every data contract, and every planned feature not yet implemented.

---

## 1. Page Inventory

| Page | Route | Status | Data Source | Notes |
|------|-------|--------|-------------|-------|
| Dashboard | `/` | **LIVE** | `useBackendData` → mock fallback | KPI cards, Pipeline Visualizer, TrendChart, MitreRadar, Recent Tickets all render. Trend/MITRE data still hardcoded from `mockData.ts` |
| Tickets | `/tickets` | **STUB** | None | Renders placeholder text only. No ticket list, no RightPanel, no filters |
| Investigations | `/investigations` | **STUB** | None | Renders placeholder text only. React Flow canvas not implemented |
| Playbooks | `/playbooks` | **STUB** | None | Renders placeholder text only. Markdown viewer not implemented |
| Trends | `/trends` | **STUB** | None | Renders placeholder text only. BarChart/PieChart/AreaChart not implemented |
| Log Ingest | `/ingest` | **PARTIAL** | `ingestFile()` → `POST /ingest_file` | Dropzone + preview + upload button wired to real backend. Missing: paste input, watchdog connectors, live log stream panel, file queue list, format auto-detection label |

### Dashboard Sub-Component Status

| Component | Status | Data Source |
|-----------|--------|-------------|
| KPI — Active Tickets | **LIVE** | `useBackendData.state.kpi.totalTickets` |
| KPI — Critical Count | **LIVE** | `useBackendData.state.kpi.criticalCount` |
| KPI — Avg CVSS | **LIVE** | `useBackendData.state.kpi.avgCvss` (derived from `anomaly_score`) |
| KPI — Layers Online | **LIVE** | `useBackendData.state.kpi.layersOnline` |
| Pipeline Visualizer | **LIVE (animated)** | `useBackendData.state.layers` — beam animation always runs; layer status updates from `/health` poll |
| Pipeline Node logs | **PARTIAL** | Real logs injected after file upload via `derivePipelineHealth()`; otherwise mock strings |
| TrendChart (7-day) | **MOCK** | `mockTrendData` from `mockData.ts` — not connected to backend |
| MITRE Radar | **MOCK** | `mockMitreData` from `mockData.ts` — not connected to backend |
| Recent Incidents table | **MOCK** | `allMockTickets` from `mockData.ts` — does not reflect live detections |
| Toast — Demo Mode | **LIVE** | Fires when `/health` returns false |
| Toast — Backend Connected | **LIVE** | Fires when `/health` returns true |
| Toast — Critical Alert | **LIVE** | Fires when live detections contain CRITICAL tickets |
| Mode badge (TopBar) | **LIVE** | Shows `⚠ DEMO MODE` or `⟳ CONNECTING` when not live |

---

## 2. Backend-to-UI Mapping

Every Python file in `/backend` mapped to its corresponding UI component or data flow.

### Layer 0 — Ingestion

| Python File | UI Component / Data Flow | Integration Status |
|-------------|--------------------------|-------------------|
| `layer_0_ingestion/fastapi_receiver.py` | `LogIngest` page → `ingestFile()` hook → `POST /ingest_file` | **WIRED** — multipart upload triggers full pipeline |
| `layer_0_ingestion/fastapi_receiver.py` → `GET /health` | `TopBar` mode badge + `useBackendData` health poll | **WIRED** — polled every 3s |
| `layer_0_ingestion/log_parsers.py` | `LogIngest` dropzone — format detection label ("Detected: Syslog / CEF / JSON") | **NOT WIRED** — format label not shown in current LogIngest UI |
| `layer_0_ingestion/log_normalizer.py` | Pipeline node "INGESTION" — `recentLogs` accordion | **PARTIAL** — logs shown after upload via `derivePipelineHealth()`, not streaming |
| `layer_0_ingestion/response_formatter.py` | `src/types/backend.ts` → `BackendDetection` interface | **WIRED** — TypeScript types match `format_enriched_log()` output shape |
| `layer_0_ingestion/test_logs.log` | `LogIngest` dropzone — test file for manual QA | **MANUAL** — not automated |

### Layer 1 — Feature Engineering

| Python File | UI Component / Data Flow | Integration Status |
|-------------|--------------------------|-------------------|
| `layer_1_feature_engineering/feature_orchestrator.py` | Pipeline node "FEATURE ENG" — status + `recentLogs` | **PARTIAL** — node status driven by health poll, not per-engine output |
| `layer_1_feature_engineering/log_classifier.py` | Pipeline node "INGESTION" — `log_family` classification | **PARTIAL** — `log_type` field in `BackendDetection` carries this value |
| `engine_1_temporal/temporal_orchestrator.py` | TrendChart — temporal event volume over time | **NOT WIRED** — TrendChart uses `mockTrendData`; temporal features not surfaced |
| `engine_1_temporal/time_window_builder.py` | KPI "Avg CVSS" trend line | **NOT WIRED** |
| `engine_1_temporal/tsfresh_extractor.py` | Anomaly Activity graph (planned AreaChart) | **NOT WIRED** |
| `engine_2_behavioral/behavioral_orchestrator.py` | UEBA flags → `Ticket.recommendations` | **WIRED** — `ueba_flags` from `engine_1_anomaly` drives recommendation text in `adapters.ts` |
| `engine_2_behavioral/user_profiler.py` | Ticket detail — affected user field | **PARTIAL** — `affected_user` from `raw_event` shown in ticket |
| `engine_2_behavioral/baseline_comparator.py` | `deviation_score` → CVSS derivation | **NOT WIRED** — `deviation_score` not in `BackendDetection` type (only in `response_formatter` output) |
| `engine_3_statistical/statistical_orchestrator.py` | Trends page — frequency analysis charts | **NOT WIRED** — Trends page is a stub |
| `engine_3_statistical/frequency_analyzer.py` | TrendChart — spike detection overlay | **NOT WIRED** |
| `engine_3_statistical/pattern_detector.py` | MITRE Radar — pattern coverage | **NOT WIRED** — MITRE Radar uses `mockMitreData` |
| `engine_4_network/network_orchestrator.py` | Investigations graph — network edge labels | **NOT WIRED** — Investigations page is a stub |
| `engine_4_network/traffic_analyzer.py` | Pipeline node "FEATURE ENG" — protocol anomaly logs | **NOT WIRED** |
| `engine_4_network/protocol_profiler.py` | Ticket detail — protocol field | **PARTIAL** — `protocol` from `raw_event` shown |
| `engine_5_web/web_orchestrator.py` | Ticket detail — HTTP method/status | **NOT WIRED** — HTTP fields not in `BackendDetection` type |
| `engine_5_web/http_analyzer.py` | Log Ingest — web log format detection | **NOT WIRED** |
| `engine_5_web/session_profiler.py` | Investigations graph — session nodes | **NOT WIRED** |
| `engine_6_iot/iot_orchestrator.py` | Pipeline node "FEATURE ENG" — IoT log handling | **PARTIAL** — `log_type: 'iot'` carried through to ticket |
| `engine_6_iot/device_profiler.py` | Ticket detail — device ID / type | **NOT WIRED** — device fields not in `BackendDetection` type |
| `engine_6_iot/telemetry_analyzer.py` | Trends page — IoT telemetry chart | **NOT WIRED** |

### Layer 2 — Detection

| Python File | UI Component / Data Flow | Integration Status |
|-------------|--------------------------|-------------------|
| `layer_2_detection/detection_orchestrator.py` | `useBackendData.ingestFile()` → full detection result | **WIRED** — orchestrator output is the root of `BackendDetection` |
| `engine_1_anomaly/anomaly_orchestrator.py` | `CVSSBadge` + `KPICard` Critical count + severity derivation | **WIRED** — `anomaly_score` drives `deriveSeverity()` and `deriveCVSS()` in `adapters.ts` |
| `engine_1_anomaly/pyod_detector.py` | `CVSSBadge` circular score | **WIRED** — `pyod_score` is part of `Engine1Anomaly` type |
| `engine_1_anomaly/ueba_scorer.py` | Ticket recommendations — off-hours flag | **WIRED** — `ueba_flags` array drives recommendation text |
| `engine_2_threat_intel/intel_orchestrator.py` | Ticket intent string + MITRE tactic display | **WIRED** — `mitre_tactic` + `mitre_technique_name` used in `deriveIntent()` |
| `engine_2_threat_intel/ioc_matcher.py` | Ticket severity escalation to CRITICAL | **WIRED** — `threat_intel_match: true` forces CRITICAL severity |
| `engine_2_threat_intel/mitre_mapper.py` | MITRE Radar chart — tactic coverage | **NOT WIRED** — Radar uses `mockMitreData`; live MITRE data not aggregated |
| `engine_3_correlation/correlation_orchestrator.py` | Ticket `actionsTaken` timeline | **WIRED** — `attack_timeline` entries become `ActionEntry[]` in `adapters.ts` |
| `engine_3_correlation/event_linker.py` | Investigations graph — edge relationships | **NOT WIRED** — `linked_events` not in `BackendDetection` TS type |
| `engine_3_correlation/timeline_builder.py` | Ticket detail — vertical timeline component | **PARTIAL** — timeline data wired, but Tickets page is a stub so it's not rendered |
| `ioc_database/ioc_db.py` | Threat intel match badge on ticket | **WIRED** — `threat_intel_match` boolean surfaced |
| `ioc_database/ioc_api.py` | Not mapped to UI | **NOT WIRED** |
| `ioc_database/auto_enricher.py` | Not mapped to UI | **NOT WIRED** |
| `layer2_output.json` | Mock fallback data reference | **REFERENCE ONLY** — not loaded by frontend |

---

## 3. Data Contract Audit

Comparing `fastapi_receiver.py → build_output()` with `src/types/backend.ts → BackendDetection`.

### ✅ Correctly Matched Fields

| Python field | TypeScript field | Notes |
|---|---|---|
| `incident_id` | `incident_id: string` | Exact match |
| `timestamp` | `timestamp: string` | Exact match |
| `log_type` | `log_type: 'network' \| 'endpoint' \| 'auth' \| 'firewall' \| 'iot'` | Exact match |
| `format` | `format?: string` | Optional, exact match |
| `raw_event.source_ip` | `RawEvent.source_ip: string \| null` | Exact match |
| `raw_event.destination_ip` | `RawEvent.destination_ip: string \| null` | Exact match |
| `raw_event.affected_user` | `RawEvent.affected_user: string \| null` | Exact match |
| `raw_event.affected_host` | `RawEvent.affected_host: string \| null` | Exact match |
| `raw_event.port` | `RawEvent.port: number \| null` | Exact match |
| `raw_event.protocol` | `RawEvent.protocol: string \| null` | Exact match |
| `raw_event.action` | `RawEvent.action: string \| null` | Exact match |
| `raw_event.timestamp` | `RawEvent.timestamp: string` | Exact match |
| `engine_1_anomaly.pyod_score` | `Engine1Anomaly.pyod_score: number` | Exact match |
| `engine_1_anomaly.is_outlier` | `Engine1Anomaly.is_outlier: boolean` | Exact match |
| `engine_1_anomaly.ueba_flags` | `Engine1Anomaly.ueba_flags: string[]` | Exact match |
| `engine_1_anomaly.anomaly_score` | `Engine1Anomaly.anomaly_score: number` | Exact match |
| `engine_1_anomaly.anomaly_flagged` | `Engine1Anomaly.anomaly_flagged: boolean` | Exact match |
| `engine_2_threat_intel.ioc_matches` | `Engine2ThreatIntel.ioc_matches: string[]` | Exact match |
| `engine_2_threat_intel.threat_intel_match` | `Engine2ThreatIntel.threat_intel_match: boolean` | Exact match |
| `engine_2_threat_intel.mitre_tactic` | `Engine2ThreatIntel.mitre_tactic: string` | Exact match |
| `engine_2_threat_intel.mitre_technique` | `Engine2ThreatIntel.mitre_technique: string` | Exact match |
| `engine_2_threat_intel.mitre_technique_name` | `Engine2ThreatIntel.mitre_technique_name: string` | Exact match |
| `engine_3_correlation.event_count` | `Engine3Correlation.event_count: number` | Exact match |
| `engine_3_correlation.attack_timeline[].timestamp` | `TimelineEntry.timestamp: string` | Exact match |
| `engine_3_correlation.attack_timeline[].event` | `TimelineEntry.event: string` | Exact match |
| `engine_3_correlation.attack_timeline[].detail` | `TimelineEntry.detail: string` | Exact match |

### ⚠️ Mismatches & Missing Fields

| Python field | TypeScript status | Severity | Fix needed |
|---|---|---|---|
| `engine_1_anomaly.fidelity_score` | **MISSING** from `Engine1Anomaly` | Low | Add `fidelity_score?: number` to `Engine1Anomaly` |
| `engine_1_anomaly.model_votes` | **MISSING** from `Engine1Anomaly` | Low | Add `model_votes?: Record<string, number>` |
| `engine_1_anomaly.ueba_risk_boost` | **MISSING** from `Engine1Anomaly` | Low | Add `ueba_risk_boost?: number` |
| `engine_1_anomaly.flag_details` | **MISSING** from `Engine1Anomaly` | Low | Add `flag_details?: Record<string, unknown>` |
| `engine_2_threat_intel.matched_ioc_details` | **MISSING** from `Engine2ThreatIntel` | Medium | Add `matched_ioc_details?: IocDetail[]` — needed for IOC detail panel |
| `engine_2_threat_intel.cis_violations` | **MISSING** from `Engine2ThreatIntel` | Low | Add `cis_violations?: string[]` |
| `engine_2_threat_intel.iot_threshold_hits` | **MISSING** from `Engine2ThreatIntel` | Low | Add `iot_threshold_hits?: string[]` |
| `engine_2_threat_intel.all_techniques` | **MISSING** from `Engine2ThreatIntel` | Medium | Add `all_techniques?: MitreTechniqueEntry[]` — needed for MITRE Radar live data |
| `engine_2_threat_intel.skipped` | **MISSING** from `Engine2ThreatIntel` | Low | Add `skipped?: boolean` |
| `engine_3_correlation.linked_events` | **MISSING** from `Engine3Correlation` | High | Add `linked_events?: LinkedEvent[]` — required for Investigations React Flow graph |
| `detection_summary` block | **MISSING** entirely | Medium | Add `detection_summary?: DetectionSummary` — useful for KPI aggregation |
| `layer1_fidelity` | **MISSING** from `BackendDetection` | Low | Add `layer1_fidelity?: number` |
| `ai_analysis` | **MISSING** from `BackendDetection` | Medium | Add `ai_analysis: null \| AiAnalysis` — placeholder for Layer 3 |
| `response_formatter.deviation_score` | **NOT in `BackendDetection`** — only in `format_enriched_log()` output | High | `deviation_score` from `behavioral_features` is used in severity derivation in Python but not exposed in the `/ingest_file` detection output. Frontend `deriveCVSS()` cannot access it. |
| `ioc_matches` typed as `string[]` | Python returns list of IOC value strings | Low | Correct — but `matched_ioc_details` (list of dicts) is richer and missing |

### 🔴 Critical Contract Gap

The `response_formatter.py → _derive_severity()` function uses `deviation_score` from `behavioral_features` to compute severity. However, `fastapi_receiver.py → build_output()` does **not** include `deviation_score` in the `BackendDetection` output. The frontend `adapters.ts → deriveSeverity()` therefore cannot replicate the Python severity logic exactly — it uses `anomaly_score` as a proxy instead. This means frontend severity labels may differ from what the Python backend would assign.

**Fix**: Either expose `deviation_score` in `build_output()`, or add a `severity` field directly to the detection output so the frontend consumes it verbatim.

---

## 4. Future Implementations

Features specified in `design.md` or referenced in code comments that are not yet visible in the UI.

### Pages — Not Yet Built

| Feature | Specified In | Priority | Notes |
|---------|-------------|----------|-------|
| Tickets page — 2-column card grid with spotlight hover | `design.md` | P1 | `TicketCard`, `TicketList`, `SpotlightCard` components not created |
| Tickets page — RightPanel with 3 tabs (Overview / Playbook / Notes) | `design.md` | P1 | `RightPanel`, `TicketDetail` components not created |
| Tickets page — Focus Mode toggle (keyboard shortcut F) | `design.md` | P2 | Not implemented |
| Tickets page — Severity + Status filter bar | `design.md` | P1 | Not implemented |
| Tickets page — Block IP / Isolate Host actions with ConfirmDialog | `design.md` | P1 | `ConfirmDialog` component not created |
| Tickets page — localStorage audit trail | `design.md` | P1 | `AuditLog` utility not created |
| Investigations page — React Flow canvas | `design.md` | P1 | `FlowCanvas`, `AttackerNode`, `EntityNode`, `ActionNode`, `TimelineNode` not created |
| Investigations page — incident selector dropdown | `design.md` | P1 | Not implemented |
| Playbooks page — split layout with markdown viewer | `design.md` | P2 | `PlaybookViewer`, `PlaybookList` not created |
| Playbooks page — download .md + print/export | `design.md` | P2 | Not implemented |
| Trends page — BarChart (30 days) + PieChart + AreaChart | `design.md` | P2 | `SeverityPie`, `CVSSArea` components not created |
| Log Ingest — paste/manual input textarea | `design.md` | P1 | Not implemented |
| Log Ingest — Watchdog connectors (file, syslog, API poller) | `design.md` | P2 | `WatchdogCard` component not created |
| Log Ingest — live log stream panel (collapsible) | `design.md` | P1 | `LogStream` component not created |
| Log Ingest — file queue list with status chips | `design.md` | P1 | Only single file supported currently |
| Log Ingest — format auto-detection label | `design.md` | P1 | `detectLogFormat()` utility not implemented in frontend |
| Log Ingest — progress bar during ingestion | `design.md` | P1 | Not implemented |
| Log Ingest — result summary ("X events extracted") | `design.md` | P1 | Not implemented |

### Shared Components — Not Yet Built

| Component | Specified In | Notes |
|-----------|-------------|-------|
| `ConfirmDialog` — 2-step with typed "CONFIRM" | `design.md` | Required for Block IP + Isolate actions |
| `AuditLog` — localStorage backed | `design.md` | Required for banking compliance |
| `SkeletonCard` — loading state matching card shape | `design.md` | Not implemented |
| `EmptyState` — custom per page | `design.md` | Not implemented |
| `RightPanel` — spring slide-in ticket detail | `design.md` | Not implemented |

### Dashboard — Partially Wired

| Feature | Status | Notes |
|---------|--------|-------|
| TrendChart — live data from `engine_1_temporal` | **NOT WIRED** | Uses `mockTrendData`; needs aggregation endpoint or client-side accumulation from detections |
| MITRE Radar — live coverage from `engine_2_threat_intel.all_techniques` | **NOT WIRED** | Uses `mockMitreData`; needs `all_techniques[]` exposed in `BackendDetection` |
| Recent Incidents — live tickets from `useBackendData.state.tickets` | **NOT WIRED** | Dashboard hardcodes `allMockTickets`; should use `state.tickets` |
| Pipeline node logs — streaming from `log_normalizer.py` | **NOT WIRED** | No SSE/WebSocket endpoint; logs only update after file upload |

### Hooks — Planned but Not Built

| Hook | Specified In | Notes |
|------|-------------|-------|
| `useTickets` | `design.md` | Planned for Tickets page; currently `useBackendData` holds all tickets |
| `useSystemStatus` | `design.md` | Planned for system health; currently inlined in `useBackendData` |
| `usePipelineLive` | `design.md` | Planned for `GET /api/pipeline/live` polling; currently only `/health` is polled |
| `useWatchdog` | `design.md` | Planned for watchdog connector state; not implemented |

### API Endpoints — Defined in Design, Not Yet Called

| Endpoint | Defined In | Frontend Status |
|----------|-----------|-----------------|
| `GET /api/tickets` | `design.md` | Not called — tickets come from `ingestFile()` only |
| `GET /api/tickets/:id` | `design.md` | Not called |
| `GET /api/playbooks` | `design.md` | Not called — uses `mockPlaybooks` |
| `GET /api/playbooks/:id` | `design.md` | Not called |
| `GET /api/system/status` | `design.md` | Not called — only `/health` is polled |
| `GET /api/trends` | `design.md` | Not called — uses `mockTrendData` |
| `GET /api/pipeline/live` | `design.md` | Not called — beam animation is client-side only |
| `POST /api/tickets/:id/notes` | `design.md` | Not called — Notes tab not built |
| `POST /api/tickets/:id/status` | `design.md` | Not called |
| `POST /api/actions/block-ip` | `design.md` | Not called — action buttons not built |
| `POST /api/actions/isolate` | `design.md` | Not called |
| `POST /api/ingest/raw` | `design.md` | Not called — paste input not built |
| `POST /api/watchdog/start` | `design.md` | Not called |
| `POST /api/watchdog/syslog` | `design.md` | Not called |
| `POST /api/watchdog/poll` | `design.md` | Not called |
| `DELETE /api/watchdog/:id` | `design.md` | Not called |

### Backend Endpoints — Not Yet Exposed by FastAPI

| Endpoint | Needed By | Notes |
|----------|-----------|-------|
| `GET /api/pipeline/live` | `PipelineVisualizer` live status | Not in `fastapi_receiver.py` — needs to be added |
| `GET /api/system/status` | `TopBar` layer dots | Not in `fastapi_receiver.py` |
| `GET /api/trends` | `TrendChart` live data | Not in `fastapi_receiver.py` |
| `GET /api/tickets` | `Tickets` page | Not in `fastapi_receiver.py` — detections are not persisted |
| `POST /api/actions/block-ip` | `TicketDetail` action bar | Not in `fastapi_receiver.py` |
| `POST /api/actions/isolate` | `TicketDetail` action bar | Not in `fastapi_receiver.py` |

---

## 5. Implementation Priority Queue

Ordered by impact on analyst workflow.

```
P1 — Tickets page (TicketCard + RightPanel + ConfirmDialog + AuditLog)
P1 — Dashboard Recent Incidents wired to state.tickets (not mockData)
P1 — Log Ingest: paste input + format detection label + result summary
P1 — ConfirmDialog + AuditLog shared components
P2 — Investigations page (React Flow canvas + node types)
P2 — Trends page (3 charts wired to aggregated detection data)
P2 — Playbooks page (markdown viewer + download)
P2 — Log Ingest: watchdog connectors + live log stream panel
P3 — Backend: add /api/pipeline/live + /api/system/status endpoints
P3 — Backend: expose deviation_score in build_output() or add severity field
P3 — Backend: expose linked_events in engine_3_correlation output
P3 — Frontend: add missing fields to Engine1Anomaly + Engine2ThreatIntel types
P3 — MITRE Radar: wire to live all_techniques[] from detections
P3 — TrendChart: accumulate detection timestamps client-side for live trend
```

---

## 6. File Map Summary

```
tuxsoc/
├── src/
│   ├── App.tsx                          LIVE — router + useBackendData + toasts
│   ├── main.tsx                         LIVE — React root
│   ├── index.css                        LIVE — design tokens + war-room theme
│   │
│   ├── api/
│   │   ├── client.ts                    LIVE — Axios instance + checkHealth()
│   │   └── adapters.ts                  LIVE — BackendDetection → Ticket mapper
│   │
│   ├── hooks/
│   │   ├── useBackendData.ts            LIVE — primary data hook (replaces useSimulation)
│   │   ├── useSimulation.ts             LEGACY — kept as reference, not used in App
│   │   └── useCountUp.ts               LIVE — KPI animation
│   │
│   ├── types/
│   │   ├── backend.ts                   LIVE — FastAPI response contracts
│   │   ├── ticket.ts                    LIVE — Ticket domain model
│   │   ├── pipeline.ts                  LIVE — PipelineLayer model
│   │   └── watchdog.ts                  LIVE — WatchdogConnection + LogLine models
│   │
│   ├── mock/
│   │   └── mockData.ts                  LIVE — fallback data (8 tickets, 8 layers, 4 playbooks)
│   │
│   ├── utils/
│   │   └── severity.ts                  LIVE — getSeverityColor, getCVSSColor, formatTimeAgo
│   │
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx              LIVE — collapse/expand, Fully Local pill
│   │   │   └── TopBar.tsx               LIVE — breadcrumb, mode badge, layer dots
│   │   ├── dashboard/
│   │   │   ├── KPICard.tsx              LIVE — count-up animation
│   │   │   ├── PipelineVisualizer.tsx   LIVE — 8-node pipeline with beams
│   │   │   ├── PipelineNode.tsx         LIVE — status dot, accordion logs, active ring
│   │   │   └── DataBeam.tsx             LIVE — animated gradient beam
│   │   ├── charts/
│   │   │   ├── TrendChart.tsx           PARTIAL — renders, data is mock
│   │   │   └── MitreRadar.tsx           PARTIAL — renders, data is mock
│   │   └── shared/
│   │       ├── SeverityBadge.tsx        LIVE
│   │       ├── CVSSBadge.tsx            LIVE
│   │       ├── StatusChip.tsx           LIVE
│   │       └── ToastSystem.tsx          LIVE — spring animation, persistent CRITICAL
│   │
│   └── pages/
│       ├── Dashboard.tsx                PARTIAL — live pipeline/KPI, mock charts/tickets
│       ├── Tickets.tsx                  STUB
│       ├── Investigations.tsx           STUB
│       ├── Playbooks.tsx                STUB
│       ├── Trends.tsx                   STUB
│       └── LogIngest.tsx                PARTIAL — upload wired, missing 2 of 3 methods
│
├── backend/
│   ├── layer_0_ingestion/
│   │   ├── fastapi_receiver.py          WIRED — POST /ingest_file, GET /health
│   │   ├── log_normalizer.py            PARTIAL — output flows through pipeline
│   │   ├── log_parsers.py               WIRED (server-side) — format not surfaced to UI
│   │   └── response_formatter.py        WIRED — shapes BackendDetection output
│   ├── layer_1_feature_engineering/
│   │   ├── feature_orchestrator.py      WIRED (server-side) — output in detection result
│   │   ├── log_classifier.py            WIRED (server-side) — log_type in BackendDetection
│   │   └── engine_*/                    PARTIAL — outputs embedded in detection, not all surfaced
│   └── layer_2_detection/
│       ├── detection_orchestrator.py    WIRED — root of BackendDetection
│       ├── engine_1_anomaly/            WIRED — anomaly_score, ueba_flags surfaced
│       ├── engine_2_threat_intel/       PARTIAL — mitre_tactic wired; all_techniques missing
│       ├── engine_3_correlation/        PARTIAL — attack_timeline wired; linked_events missing
│       └── ioc_database/               PARTIAL — threat_intel_match boolean surfaced
│
├── BACKEND.md                           LIVE — setup + run guide
└── INTEGRATION_MAP.md                   THIS FILE
```
