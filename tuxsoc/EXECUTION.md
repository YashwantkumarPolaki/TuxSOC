# TuxSOC — Full Pipeline Execution Guide

How to run the complete 6-layer pipeline so that uploading a JSON file in the Log Ingest UI automatically processes through all layers and surfaces a Playbook in the frontend.

---

## Architecture Overview

```
Browser (Log Ingest UI)
  │  POST /ingest_file  (multipart JSON/CSV/Excel)
  ▼
FastAPI  ingestion/fastapi_receiver.py  :8000
  │  calls
  ▼
main_orchestrator.run_pipeline()
  ├── Layer 0  ingestion/log_normalizer.py        — field mapping, timestamp normalisation
  ├── Layer 1  layer_1_feature_engineering/        — temporal, behavioral, statistical, identity
  ├── Layer 2  main_orchestrator._layer2_detect()  — anomaly scores, MITRE mapping, risk score
  ├── Layer 3  (optional) layer_3_ai_analysis/     — Ollama AI intent (requires ?run_ai=true)
  ├── Layer 4  main_orchestrator._layer4_cvss()    — CVSS base score derivation
  └── Layer 5  main_orchestrator._layer5_playbook()— playbook selection from MITRE tactic
  │
  └── Returns BackendDetection[] with suggested_playbook embedded
  │
  ▼
React frontend
  ├── useBackendData.ingestFile()  — stores rawDetections + tickets in state
  ├── Tickets.tsx                  — debug view: Layer 1 + Layer 2 per card
  ├── Playbooks.tsx                — response playbook viewer (auto-navigated after upload)
  └── Dashboard.tsx                — KPI cards + pipeline visualizer
```

---

## Step 1 — Start the Backend

Open a terminal and run from the `tuxsoc/backend/` directory:

```powershell
# Windows
cd tuxsoc\backend
.venv\Scripts\activate
uvicorn ingestion.fastapi_receiver:app --host 0.0.0.0 --port 8000 --reload
```

```bash
# macOS / Linux
cd tuxsoc/backend
source .venv/bin/activate
uvicorn ingestion.fastapi_receiver:app --host 0.0.0.0 --port 8000 --reload
```

Expected output:
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Application startup complete.
```

Verify it's alive:
```bash
curl http://localhost:8000/health
# → {"status":"healthy","service":"TuxSOC Ingestion API"}
```

---

## Step 2 — Install Dependencies (first time only)

```bash
pip install fastapi uvicorn python-multipart python-dateutil \
            pyod scikit-learn numpy pandas openpyxl
```

---

## Step 3 — Start the Frontend

Open a second terminal:

```powershell
cd tuxsoc
npm install        # first time only
npm run dev
```

Open `http://localhost:5173` in your browser.

The TopBar will show **"Backend Connected"** (green toast) within 3 seconds once the FastAPI server is running.

---

## Step 4 — Upload a JSON Log File

1. Click **Log Ingest** in the left sidebar
2. Drag and drop your JSON file (e.g. `se1.json`) onto the drop zone
3. Click **"Inject into Pipeline"**

The button label changes to **"Processing through 6 layers..."** while the pipeline runs.

---

## Step 5 — Automatic Playbook Navigation

After processing completes:

1. A green toast appears: `"N events processed — N playbooks generated"`
2. After 1.2 seconds the app **automatically navigates to the Playbooks page**
3. The left panel lists one entry per detection, grouped by assigned playbook
4. Click any entry to see the full step-by-step response guide and auto-remediation actions

---

## Step 6 — Inspect the Debug View

Click **Tickets** in the sidebar to see the Feature Extraction Debug View:

Each card shows:
- **Layer 0** — log_type, source_ip, affected_user, action
- **Layer 1** — temporal features (event counts, off-hours), behavioral features (deviation score, new IP), identity features (risk_state, suspicious IP) for Azure/O365 logs
- **Layer 2** — pyod_score, anomaly_score, UEBA flags, MITRE tactic, risk score
- **Layer 4** — CVSS base score and severity
- **Layer 3** — AI analysis (shows "in progress" unless `?run_ai=true` was used)

---

## Optional: Enable Layer 3 AI Analysis (Ollama)

Layer 3 is disabled by default because it requires Ollama to be running.

To enable it, start Ollama first:
```bash
ollama serve
ollama pull llama3.2
```

Then upload with the `run_ai=true` query parameter. You can test this directly:
```bash
curl -X POST "http://localhost:8000/ingest_file?run_ai=true" \
  -F "file=@se1.json"
```

Or modify `useBackendData.ts` to append `?run_ai=true` to the `/ingest_file` POST URL.

---

## Playbook Mapping Logic

The pipeline selects playbooks based on action keywords and MITRE tactic:

| Trigger | Playbook |
|---------|----------|
| `new-inboxrule`, `forwardto` | PB-006 — Inbox Rule Abuse |
| `filedownloaded`, `exfil` | PB-002 — Data Exfiltration |
| `ransomware`, `vssadmin`, `lsass` | PB-004 — Ransomware |
| `brute`, `spray`, `login_failed` | PB-005 — Brute Force |
| `lateral`, SMB/RDP | PB-003 — Lateral Movement |
| `sign-in`, `mailitemsaccessed` | PB-001 — Account Compromise |
| MITRE tactic: Exfiltration/Collection | PB-002 — Data Exfiltration |
| MITRE tactic: Credential Access | PB-005 — Brute Force |
| MITRE tactic: Impact/Execution | PB-004 — Ransomware |
| Fallback | PB-000 — Generic Response |

---

## Pipeline Status API

While a file is being processed, the frontend polls:
```
GET http://localhost:8000/pipeline/status
```

Response:
```json
{
  "layer_0": "done",
  "layer_1": "done",
  "layer_2": "done",
  "layer_3": "idle",
  "layer_4": "done",
  "layer_5": "idle",
  "last_run": "2026-03-29T03:44:12Z",
  "records_processed": 10
}
```

The PipelineVisualizer nodes on the Dashboard light up as each layer transitions from `idle` → `active` → `done`.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ERR_CONNECTION_REFUSED` on port 8000 | Backend not running — run Step 1 |
| `ModuleNotFoundError` on startup | Run uvicorn from `tuxsoc/backend/` not from inside `ingestion/` |
| Frontend shows "Demo Mode" | Backend health check failing — verify port 8000 is reachable |
| All fields show `null` in debug view | Azure field mapping issue — check `IpAddress`/`UserPrincipalName` keys in your JSON |
| Playbooks page is empty | Upload a file first — playbooks are generated per-upload, not persisted |
| Layer 3 shows "in progress" | Expected — Ollama is off by default. Enable with `?run_ai=true` |
