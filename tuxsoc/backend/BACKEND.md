# TuxSOC Backend — Setup & Run Guide

## Architecture Overview

```
tuxsoc/backend/
├── layer_0_ingestion/          ← FastAPI receiver + log parsers + normalizer
│   ├── fastapi_receiver.py     ← Main API server (POST /ingest_file, GET /health)
│   ├── log_normalizer.py       ← ECS flat-schema normalizer
│   ├── log_parsers.py          ← Multi-format parser (syslog, CEF, JSON, CSV, IoT)
│   └── response_formatter.py  ← Shapes enriched logs into SOC response schema
│
├── layer_1_feature_engineering/
│   ├── feature_orchestrator.py ← Runs all 6 engines in sequence
│   ├── log_classifier.py       ← Scores log family (network/web/iot)
│   ├── engine_1_temporal/      ← Time-window features (off-hours, event velocity)
│   ├── engine_2_behavioral/    ← User baseline deviation scoring
│   ├── engine_3_statistical/   ← Frequency analysis, spike detection
│   ├── engine_4_network/       ← Protocol anomaly, traffic patterns
│   ├── engine_5_web/           ← HTTP session profiling
│   └── engine_6_iot/           ← MQTT/telemetry device profiling
│
└── layer_2_detection/
    ├── detection_orchestrator.py  ← Runs E1→E2→E3 in conditional sequence
    ├── engine_1_anomaly/          ← PyOD outlier detection + UEBA scoring
    ├── engine_2_threat_intel/     ← IOC matching + MITRE ATT&CK mapping
    ├── engine_3_correlation/      ← Event linking + attack timeline builder
    └── ioc_database/              ← SQLite IOC store (auto-seeded)
```

## Prerequisites

- Python 3.11+
- pip

## Installation

```bash
# From the tuxsoc/backend directory
cd tuxsoc/backend

# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (macOS/Linux)
source .venv/bin/activate

# Install dependencies
pip install fastapi uvicorn python-multipart python-dateutil pyod scikit-learn numpy pandas tsfresh
```

## Running the Backend

```bash
# From tuxsoc/backend/layer_0_ingestion/
cd layer_0_ingestion

uvicorn fastapi_receiver:app --host 0.0.0.0 --port 8000 --reload
```


Analysis
python -m layer_3_ai_analysis.app


The API will be available at: **http://localhost:8000**

## API Endpoints

| Method | Endpoint       | Description                                      |
|--------|---------------|--------------------------------------------------|
| GET    | `/health`      | Health check — returns `{"status": "healthy"}`  |
| POST   | `/ingest_file` | Upload a log file → full pipeline → detections  |
| GET    | `/docs`        | Interactive Swagger UI                           |

## Testing the Pipeline

### Health check
```bash
curl http://localhost:8000/health
```

### Ingest a log file
```bash
curl -X POST http://localhost:8000/ingest_file \
  -F "file=@layer_0_ingestion/test_logs.log"
```

### Expected response shape
```json
{
  "status": "success",
  "file": "test_logs.log",
  "total_processed": 25,
  "detections": [
    {
      "incident_id": "INC-2024-0403-SOC-3B43256B",
      "timestamp": "2024-04-03T21:27:39Z",
      "log_type": "iot",
      "raw_event": {
        "source_ip": "192.168.10.201",
        "destination_ip": "185.156.73.54",
        "affected_host": "sensor-009",
        "port": 1883,
        "protocol": "mqtt",
        "action": "IoT sensor MQTT flood to external broker - botnet C2"
      },
      "engine_1_anomaly": {
        "pyod_score": 0.7556,
        "is_outlier": true,
        "ueba_flags": ["off_hours_activity"],
        "anomaly_score": 0.8556,
        "anomaly_flagged": true
      },
      "engine_2_threat_intel": {
        "ioc_matches": [],
        "threat_intel_match": false,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1078",
        "mitre_technique_name": "Valid Accounts"
      },
      "engine_3_correlation": {
        "event_count": 2,
        "attack_timeline": [
          {
            "timestamp": "2024-04-03T21:27:39+00:00",
            "event": "firewall_action",
            "detail": "IOT SENSOR MQTT FLOOD from 192.168.10.201 → 185.156.73.54 on port 1883"
          }
        ]
      }
    }
  ]
}
```

## Frontend Integration

The React frontend connects to `http://localhost:8000` by default.

To override, set the environment variable before running `npm run dev`:

```bash
# Windows (PowerShell)
$env:VITE_API_BASE_URL = "http://your-server:8000"
npm run dev

# macOS/Linux
VITE_API_BASE_URL=http://your-server:8000 npm run dev
```

## Severity Mapping (Backend → Frontend)

| Condition                                    | Frontend Severity |
|----------------------------------------------|-------------------|
| `anomaly_score >= 0.85` OR IOC match         | CRITICAL          |
| `anomaly_score >= 0.70` OR lateral movement  | HIGH              |
| `anomaly_score >= 0.55` OR UEBA flags        | MEDIUM            |
| All others                                   | LOW               |

## CVSS Score Derivation

```
cvss = min(10, anomaly_score × 10 + (0.5 if ioc_match else 0))
```

## Pipeline Layer → Backend Mapping

| UI Pipeline Node  | Backend Component                        |
|-------------------|------------------------------------------|
| LOG SOURCES       | Log file / syslog input                  |
| INGESTION         | `fastapi_receiver.py` + `log_parsers.py` |
| FEATURE ENG       | `feature_orchestrator.py` (6 engines)    |
| DETECTION         | `detection_orchestrator.py` (E1+E2+E3)  |
| AI ANALYSIS       | Engine 2 MITRE mapping + UEBA            |
| CVSS              | Derived from `anomaly_score`             |
| RESPONSE          | `response_formatter.py`                  |
| DASHBOARD         | React frontend                           |

## Offline / Demo Mode

If the backend is unreachable, the frontend automatically:
1. Shows a **"Offline — Demo Mode"** amber toast in the bottom-right
2. Continues running with mock data (all pipeline animations remain active)
3. Re-checks backend health every 3 seconds
4. Switches to **"Backend Connected"** green toast when backend comes online

## CORS

The backend has CORS enabled for all origins in development. For production, restrict to your frontend domain in `fastapi_receiver.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev server
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: feature_orchestrator` | Run uvicorn from `layer_0_ingestion/` directory |
| `IOC DB init warning` | Normal on first run — SQLite DB is auto-created |
| `PyOD model not found` | Run `python layer_2_detection/training/train_pyod.py` first |
| Frontend shows "Demo Mode" | Ensure backend is running on port 8000 |
