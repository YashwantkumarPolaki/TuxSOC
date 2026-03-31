# Bugfix Requirements Document

## Introduction

The TuxSOC 7-layer backend pipeline (`main_orchestrator.py`) produces a rich `BackendDetection` JSON structure covering Layers 0–5. Several fields produced by Layer 3 (AI), Layer 4 (CVSS), and Layer 5 (Response/Playbook) are either not reaching the React frontend correctly, are mapped to the wrong source, or are silently dropped during the `detectionToTicket` adapter transform. Additionally, the Playbooks page lists every individual detection instead of surfacing one comprehensive playbook per active incident, and KPI counters (`totalTickets`, `avgCvss`) are computed from a filtered subset rather than the full aggregated detection list. These bugs collectively break the "wire-to-wire" contract between the backend pipeline and the frontend UI.

This document also captures the requirements for a new **Batch-Aware sequential pipeline** feature. The system must accept a JSON payload containing multiple log entries (e.g. 10 lines), correlate them into a single unified incident by shared Source IP or Destination, and produce one consolidated AI analysis, one CVSS score, and one master Playbook for the entire batch — while keeping individual log entries visible in the Tickets Feed linked to the same `parent_incident_id`.

---

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN the backend returns a detection where `layer4_cvss.base_score` is `0.0` and `layer4_cvss.severity` is `"NONE"` (e.g. individual correlated sub-events) THEN the frontend `deriveCVSS()` function still reads `layer4_cvss.base_score` and displays `0.0` instead of falling back to the anomaly-score formula, producing misleading CVSS badges.

1.2 WHEN the backend returns a detection where `layer4_cvss.severity` is `"NONE"` THEN `deriveSeverity()` casts it directly to `Severity` without validation, causing the severity badge to display `"NONE"` — a value not in the `Severity` union type.

1.3 WHEN the backend returns `ai_analysis` with a non-null `summary` field THEN the `Ticket.aiAnalysis` object is populated, but the `Playbooks.tsx` page never reads or renders `aiAnalysis.summary`, so the AI Insights text is silently discarded in the playbook view.

1.4 WHEN the backend returns a detection with `ai_analysis: null` (Ollama offline) THEN `deriveIntent()` falls through to the `logType + sourceIp` fallback, but if `raw_event.action` is also `null` or `"Unknown"` and `raw_event.source_ip` is `null`, the ticket title renders as `"Network activity from unknown source"` — an uninformative label that does not use the available `incident_id`.

1.5 WHEN the backend returns a master incident (`is_master: true`) with `suggested_playbook.steps` populated from flattened phases THEN `Playbooks.tsx` renders the flat `steps` array in the `PhasedPlaybook` fallback branch instead of the `phases` array, because the `phases` field is present but the component checks `phases.length === 0` only after confirming `phases` is truthy — this path is correct, but individual non-master detections whose `suggested_playbook` has `phases: null` hit the flat-steps branch correctly; however the `autoRemediation` field is mapped from `pb.auto_remediation` (snake_case) in the backend but the `Ticket` type stores it as `autoRemediation` (camelCase) — the adapter correctly maps this, yet `deriveSuggestedPlaybook` reads `pb.auto_remediation` from the raw `BackendDetection`, which is correct; the bug is that `SuggestedPlaybook` in `backend.ts` declares the field as `auto_remediation` but the `Ticket` type declares it as `autoRemediation`, and the adapter bridges them — this is working, but the `backend.ts` type is missing the `web` and `iot` log-type values from the `log_type` union, causing TypeScript to flag detections with those types.

1.6 WHEN the `Playbooks` page renders THEN it lists every ticket that has a `suggestedPlaybook` (potentially dozens of individual sub-events) in the left panel, rather than showing one consolidated playbook per active incident, making the panel unusable at scale.

1.7 WHEN `useBackendData.ingestFile` processes a response THEN `kpi.totalTickets` is set to `newTickets.filter(t => t.status !== 'RESOLVED').length` and `kpi.avgCvss` is computed from `newTickets` — but `newTickets` is derived only from the current ingest batch; if the user navigates away and back, the `state.tickets` array persists (React state is in-memory) but the KPI values are not recomputed on navigation, so the displayed KPIs can drift from the actual ticket list.

1.8 WHEN the backend returns `engine_3_correlation.attack_timeline` entries for a master incident THEN the timeline contains duplicate entries (the same `incident_id` appears multiple times because each correlated sub-detection contributes its own timeline), causing the `actionsTaken` array in the ticket to contain repeated entries.

1.9 WHEN `raw_event.action` is `null` and `raw_event.source_ip` is `null` and `engine_2_threat_intel.mitre_tactic` is `"Unknown"` THEN `deriveIntent()` returns `"Network activity from unknown source"` — the `incident_id` is never used as a fallback label component, so tickets appear as generic unnamed entries.

1.10 WHEN the backend `layer4_cvss` module returns `severity: "NONE"` for low-confidence sub-events THEN `deriveSeverity()` in `adapters.ts` accepts it as a valid `Severity` value and returns it, but `"NONE"` is not a member of the `Severity` type, causing a runtime type mismatch that can break severity-dependent UI components.

1.11 WHEN a multi-log JSON batch is submitted to the ingestion endpoint THEN the pipeline processes each log independently through Layers 1 and 2 without grouping them, so no correlation step runs before Layer 3, and the AI receives isolated single-event contexts instead of the full batch relationship.

1.12 WHEN multiple logs in a batch share the same Source IP or Destination THEN the system does not group them into a single incident before Layer 3, so the AI cannot identify multi-stage attack patterns (e.g. reconnaissance followed by unauthorized access) spanning the batch.

1.13 WHEN a batch of logs is processed THEN Layer 4 (CVSS) generates one score per individual detection rather than one consolidated score representing the highest risk across the entire correlated incident.

1.14 WHEN a batch of logs is processed THEN Layer 5 (Response) generates one playbook per individual detection rather than one master Playbook for the unified incident, causing `Playbooks.tsx` to render multiple entries for what is logically a single attack.

1.15 WHEN a batch of correlated logs is processed THEN the generated playbook steps do not reference the batch context (e.g. "Block IP X which was observed in N correlated events"), producing generic steps that lack batch-aware remediation guidance.

1.16 WHEN a multi-log JSON batch is ingested THEN `useBackendData.ingestFile` issues one state update per detection rather than a single atomic state update for the entire batch, causing the Playbooks page to re-render incrementally and potentially display a partially-built incident.

1.17 WHEN the user navigates away from the Playbooks page and returns THEN the in-memory batch correlation state is not preserved, so the unified incident disappears and individual sub-events are shown without their `parent_incident_id` linkage.

1.18 WHEN the main incident header is rendered for a batch THEN the title does not follow the `[Threat Level] [Primary Tactic] - [Batch Count] Events` format, making it impossible to distinguish batch incidents from single-event incidents at a glance.

---

### Expected Behavior (Correct)

2.1 WHEN `layer4_cvss.base_score` is `0.0` or `layer4_cvss.severity` is `"NONE"` or absent THEN `deriveCVSS()` SHALL fall back to the anomaly-score formula (`anomaly_score * 10 + ioc_bonus`) so that every ticket displays a meaningful CVSS value.

2.2 WHEN `layer4_cvss.severity` is `"NONE"` or any value outside `{ CRITICAL, HIGH, MEDIUM, LOW }` THEN `deriveSeverity()` SHALL ignore it and derive severity from the anomaly score and IOC match flags, returning a valid `Severity` member.

2.3 WHEN `ai_analysis.summary` is non-null THEN the `Playbooks` page SHALL render an "AI Insights" section within the `PlaybookViewer` component, displaying the summary text below the incident header.

2.4 WHEN `raw_event.action` is null/unknown AND `raw_event.source_ip` is null THEN `deriveIntent()` SHALL return a title in the format `[LogType] Event: [incident_id]` (e.g. `"Auth Event: INC-9CB0579DEC85"`) so every ticket has a unique, identifiable label.

2.5 WHEN the `Playbooks` page renders with tickets in state THEN it SHALL display one entry per unique `incident_id` in the left panel, grouping correlated sub-events under their master incident, so the panel shows at most one entry per logical incident.

2.6 WHEN `ingestFile` completes or when the component re-renders after navigation THEN `kpi.totalTickets` and `kpi.avgCvss` SHALL be computed from the full `state.tickets` array at render time, not cached from the last ingest batch, so KPI values always reflect the current ticket list.

2.7 WHEN `engine_3_correlation.attack_timeline` contains duplicate `incident_id` entries THEN `deriveActions()` SHALL deduplicate timeline entries by `incident_id + timestamp` before mapping them to `ActionEntry` objects, so `actionsTaken` contains no repeated rows.

2.8 WHEN `raw_event.action` is null/unknown AND `raw_event.source_ip` is null AND `engine_2_threat_intel.mitre_tactic` is `"Unknown"` THEN `deriveIntent()` SHALL use the `incident_id` as the unique identifier component in the fallback title.

2.9 WHEN `layer4_cvss.severity` is `"NONE"` THEN `deriveSeverity()` SHALL treat it as absent and proceed to the anomaly-score branch, returning a valid `Severity` value.

2.10 WHEN the `BackendDetection` type is declared in `backend.ts` THEN the `log_type` union SHALL include `'web'` and `'iot'` to match all values the backend can emit, preventing TypeScript type errors on valid backend responses.

2.11 WHEN a multi-log JSON batch is submitted (L0 Ingestion) THEN the pipeline SHALL accept the full array of log entries and pass all of them through Layers 1 and 2, ensuring all 3 detection engines run on every log in the batch before any correlation step.

2.12 WHEN Layer 2 processing completes for a batch THEN the system SHALL run a correlation step that groups logs sharing the same Source IP or Destination into a single Incident before passing data to Layer 3, so the AI receives the entire correlated batch as one context.

2.13 WHEN the correlated batch is passed to Layer 3 (AI Analysis) THEN the AI SHALL analyze the relationship between all logs in the batch and produce a unified narrative (e.g. "This is a multi-stage attack starting with reconnaissance and ending in unauthorized access") covering the full incident.

2.14 WHEN Layer 3 analysis completes for a correlated batch THEN Layer 4 (CVSS) SHALL generate one consolidated CVSS score for the whole incident, derived from the highest-risk finding across all logs in the batch.

2.15 WHEN Layer 4 produces a consolidated CVSS score THEN Layer 5 (Response) SHALL generate exactly ONE master Playbook for the unified incident, with steps that are batch-aware (e.g. "Block IP 203.x.x.x which was observed in 10 correlated events").

2.16 WHEN a multi-log JSON batch is ingested THEN `useBackendData.ingestFile` SHALL issue a single atomic state update for the entire batch, so `Playbooks.tsx` renders the complete unified incident in one pass rather than incrementally.

2.17 WHEN the user navigates between Dashboard, Tickets, and Playbooks pages THEN the in-memory batch correlation state SHALL be preserved, and all individual log entries SHALL remain linked to their `parent_incident_id` without being cleared.

2.18 WHEN the main incident header is rendered for a batch incident THEN the title SHALL follow the format `[Threat Level] [Primary Tactic] - [Batch Count] Events` (e.g. `"CRITICAL Lateral Movement - 10 Events"`) to clearly distinguish batch incidents from single-event incidents.

---

### Unchanged Behavior (Regression Prevention)

3.1 WHEN `layer4_cvss.base_score` is a positive number and `layer4_cvss.severity` is a valid `Severity` value THEN the system SHALL CONTINUE TO use the Layer 4 score as the authoritative CVSS value, not the anomaly-score fallback.

3.2 WHEN `ai_analysis.intent` is non-null THEN `deriveIntent()` SHALL CONTINUE TO return the AI intent string as the ticket title with highest priority.

3.3 WHEN a master incident (`is_master: true`) has `suggested_playbook.phases` populated THEN `PhasedPlaybook` SHALL CONTINUE TO render the phased layout with per-phase color coding and icons.

3.4 WHEN `suggested_playbook.kill_chain` is present on a master incident THEN `AttackPath` SHALL CONTINUE TO render the kill-chain timeline in the left column of the two-column playbook layout.

3.5 WHEN `suggested_playbook.dora_flags` is present THEN the DORA flags section SHALL CONTINUE TO render in the `AttackPath` component.

3.6 WHEN the user navigates between Dashboard, Tickets, and Playbooks THEN `state.tickets` and `state.rawDetections` SHALL CONTINUE TO persist in React state without being cleared, as `useBackendData` is mounted at the `AppShell` level.

3.7 WHEN `ingestFile` is called THEN the existing Framer Motion animations and Tailwind theme classes SHALL CONTINUE TO be unmodified.

3.8 WHEN `engine_2_threat_intel.mitre_tactic` is a real tactic name (not `"Unknown"`) THEN `deriveMitreTactics()` SHALL CONTINUE TO return it as the single-element array.

3.9 WHEN `suggested_playbook.auto_remediation` contains entries THEN the Auto-Remediation section in `PlaybookViewer` SHALL CONTINUE TO render all entries with the green checkmark icon.

3.10 WHEN the backend returns `threat_intel_match: true` THEN `buildRecommendations()` SHALL CONTINUE TO append the IOC escalation recommendation to the ticket.

3.11 WHEN a batch is processed and correlated into a master incident THEN individual log entries SHALL CONTINUE TO appear in the Tickets Feed, each retaining its own raw event data and linked to the master via `parent_incident_id`.

3.12 WHEN a batch incident is displayed in `Playbooks.tsx` THEN the page SHALL CONTINUE TO render exactly one playbook entry for the ingested file, not one per sub-event.

3.13 WHEN a single-log (non-batch) JSON is submitted THEN the pipeline SHALL CONTINUE TO process it through the existing single-event flow without requiring a correlation step, and the existing playbook selection logic SHALL remain unchanged.

3.14 WHEN the Deep Stealth UI theme is applied THEN all batch-aware components (batch incident header, correlated event count badge, `parent_incident_id` link in Tickets Feed) SHALL CONTINUE TO use the existing Deep Stealth color palette and Tailwind theme classes without introducing new theme overrides.
