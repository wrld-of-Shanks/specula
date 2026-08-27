# Specula — HORUS Security Scanner

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Node](https://img.shields.io/badge/Node.js-%3E%3D20-339933?logo=node.js&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-105%20passing-brightgreen)
![Made with](https://img.shields.io/badge/made%20with-pdf--lib%20%7C%20nodemailer%20%7C%20XGBoost%20%7C%20CodeBERT-8A2BE2)

A locally-trained security platform combining **network intrusion detection**, **source-code vulnerability detection**, and **dynamic application security testing** under one confidence-based triage system.

## Features

- **NIDS (Module 1)** — XGBoost + Isolation Forest ensemble on NSL-KDD (23 attack classes)
- **SAST (Module 2)** — Fine-tuned CodeBERT classifier (7 CWE classes), CodeT5 fix generator, rule engine, and full GitHub **repo scanner**
- **DAST (Module 3)** — 8 passive checks + 5 active probes behind an authorization gate
- **Confidence-based triage** — auto-flag / human-review / ignore thresholds with CWE explanations
- **Auto-Fix & PRs** — one-click fix generation with GitHub pull requests (or report-only issues)
- **📊 Automated Security Reports** — generate PDF reports of scan findings and download them from the dashboard
- **📢 Notifications** — Slack webhook + SMTP email summaries with a link to the generated report
- **Live WebSocket threat feed** and **OpenAPI** (Swagger) docs at `/api-docs`

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    React Dashboard (3001)                        │
│  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
│  │ Threat Feed  │  │  Unified Scanner │  │  Live Stats       │  │
│  │ (WebSocket)  │  │  (SAST/DAST/Repo)│  │  (Events/Severity)│  │
│  └──────────────┘  └──────────────────┘  └───────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │ WebSocket + HTTP
┌──────────────────────────────▼──────────────────────────────────┐
│              Node.js/Express Gateway (3000)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐  │
│  │  Router      │  │  WS Server  │  │  Triage Engine         │  │
│  └─────────────┘  └─────────────┘  └────────────────────────┘  │
└───────┬────────────────────┬──────────────────┬────────────────┘
        │ HTTP               │ HTTP             │ HTTP
┌───────▼─────────┐ ┌───────▼──────────┐ ┌─────▼───────────────┐
│ Network Service │ │  Code Service    │ │  DAST Service       │
│ (Flask) (5001)  │ │  (Flask) (5002)  │ │  (Flask) (5003)     │
│ ┌─────────────┐ │ │  ┌─────────────┐ │ │  ┌────────────────┐ │
│ │ XGBoost     │ │ │  │ CodeBERT    │ │ │  │ Passive Checks │ │
│ │ Isolation   │ │ │  │ Classifier  │ │ │  │ (8 checks)     │ │
│ │ Forest      │ │ │  ├─────────────┤ │ │  ├────────────────┤ │
│ └─────────────┘ │ │  │ CodeT5      │ │ │  │ Active Probes  │ │
│                 │ │  │ Fix Gen     │ │ │  │ (SQLi/XSS/IDOR)│ │
│                 │ │  ├─────────────┤ │ │  └────────────────┘ │
│                 │ │  │ CWE KB      │ │ │                     │
│                 │ │  └─────────────┘ │ │                     │
│                 │ │  ┌─────────────┐ │ │                     │
│                 │ │  │ Repo Scanner│ │ │                     │
│                 │ │  └─────────────┘ │ │                     │
└───────┬─────────┘ └───────┬──────────┘ └─────┬───────────────┘
        │                   │                   │
        └──────────┬────────┴───────────────────┘
            ┌──────▼──────────────────────────────────────────────┐
            │              MongoDB (27017)                        │
            │  events (network | code | dast | scan_repo)        │
            └────────────────────────────────────────────────────┘
```

## Hard Constraint

**No external inference APIs** in the runtime path. Every model is trained/fine-tuned on local hardware. Pretrained weight downloads at setup are fine; runtime API calls to hosted models are not.

## Quick Start (Docker)

```bash
# 1. Create your environment file and fill in the REQUIRED credentials
#    (MONGO_USERNAME, MONGO_PASSWORD, API_KEY). Generate an API_KEY with:
#    openssl rand -hex 32
cp .env.example .env

# 2. Build and start the full stack
docker-compose up --build

# 3. Verify all services are healthy
curl http://localhost:3000/health
```

The stack fails fast if required credentials are missing. MongoDB runs with
authentication enabled and its port is **not** exposed to the host; only the
gateway (3000) and dashboard (3001) are published.

### Required Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MONGO_USERNAME` | Yes | MongoDB root username |
| `MONGO_PASSWORD` | Yes | MongoDB root password |
| `API_KEY` | Yes | Gateway API key (client sends `X-Api-Key`) |

### Local Development (no Docker)

```bash
# 1. Create credentials file and start MongoDB with auth
cp .env.example .env

# 2. Install dependencies
cd backend/gateway && npm install
cd ../services/network && pip install -r requirements.txt
cd ../services/code && pip install -r requirements.txt
cd ../services/dast && pip install -r requirements.txt
cd ../../frontend/dashboard && npm install

# 3. Validate environment, then start all services
./scripts/check-env.sh
./scripts/start-all.sh
```

## Modules

### Module 1 — Network Anomaly Detection (NIDS)
- **Model A (Supervised):** XGBoost classifier on NSL-KDD (23 attack classes)
- **Model B (Unsupervised):** Isolation Forest for novel attack patterns
- **Ensemble:** IF anomaly score overrides XGBoost when confidence is low
- **Output:** Predicted class + anomaly score + confidence + CWE explanation

### Module 2 — Code Vulnerability Detection (SAST)
- **Classifier:** Fine-tuned CodeBERT (7 CWE classes + "not vulnerable")
- **Fix Generator:** Fine-tuned CodeT5 (seq2seq)
- **Rule Engine:** Pattern-based classifier (87% accuracy, 0% FP on parameterized queries)
- **Repo Scanner:** Clone any GitHub repo, scan every source file, stream findings

### Module 3 — Dynamic Application Security Testing (DAST)
- **Passive Checks (8):** CSP, HSTS, X-Frame-Options, cookies, CORS, TLS, error disclosure, server banner
- **Active Probes (5):** SQL injection, XSS reflection, IDOR, auth bypass, endpoint discovery
- **Authorization Gate:** External targets auto-authorized on first scan; localhost always allowed

### Triage Engine
- **Confirmed findings** (passive DAST): No confidence % — severity drives triage directly
- **Inferred findings** (active probes, ML): Confidence % with strength labels

| Confidence | Action |
|------------|--------|
| ≥ 0.90 | Auto-flag (high priority) |
| 0.50 – 0.90 | Human review |
| < 0.50 | Ignore |

## API Endpoints

### Gateway (port 3000)

> Interactive OpenAPI docs: `http://localhost:3000/api-docs` (Swagger UI).
> Machine-readable spec: `http://localhost:3000/api-docs.json`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/network/analyze` | Analyze network flow |
| POST | `/api/code/scan` | Scan code snippet |
| POST | `/api/code/scan-repo` | Start repo scan |
| GET | `/api/code/scan-repo` | List repo scan jobs |
| GET | `/api/code/scan-repo/:jobId` | Poll repo scan status |
| POST | `/api/dast/scan` | Run DAST scan |
| GET | `/api/dast/authorized-targets` | List authorized targets |
| POST | `/api/dast/authorized-targets` | Add authorized target |
| DELETE | `/api/dast/authorized-targets/:target` | Remove target |
| GET | `/api/events` | Get all events |
| GET | `/api/events/stats/summary` | Event statistics |
| POST | `/api/reports/generate` | Generate a PDF report (job or time range) |
| GET | `/api/reports/reports/:filename` | Download a generated PDF report |
| POST | `/api/notifications/send` | Send Slack/email summary notification |
| WS | `/ws` | Real-time event stream |

### Network Service (port 5001)
- `POST /predict` — Predict network traffic class
- `GET /health` — Health check

### Code Service (port 5002)
- `POST /scan` — Scan code for vulnerabilities
- `POST /fix` — Generate suggested fix
- `POST /repo-scan` — Start background repo scan
- `GET /repo-scan` — List all repo scans
- `GET /repo-scan/:jobId` — Get scan status
- `GET /health` — Health check

### DAST Service (port 5003)
- `POST /scan` — Run passive + active DAST scan
- `GET /health` — Health check

## Project Structure

```
Specula/
├── frontend/
│   └── dashboard/            # React UI (3001)
│       ├── src/components/   # ThreatFeed, UnifiedScanner, StatsBar
│       ├── src/services/     # API client, WebSocket
│       └── build/            # Production build
├── backend/
│   ├── gateway/              # Node.js/Express API gateway (3000)
│   │   ├── routes/           # code, dast, network, events, report, notification
│   │   └── __tests__/        # 105 passing tests (helpers, validation, routes)
│   ├── services/
│   │   ├── network/          # Flask — NIDS (5001)
│   │   │   └── models/       # XGBoost, Isolation Forest
│   │   ├── code/             # Flask — SAST (5002)
│   │   │   ├── models/       # CodeBERT, CodeT5, Rule Classifier
│   │   │   └── repo_scanner.py
│   │   └── dast/             # Flask — DAST (5003)
│   │       └── active_scanner.py
│   └── shared/               # middleware, schemas, triage engine
├── scripts/                  # Training, evaluation, ablation
├── docs/                     # Paper sections, evaluation reports
├── data/                     # NSL-KDD, CVE datasets
├── Dockerfile.*              # Per-service Docker builds
└── docker-compose.yml        # Full stack orchestration
```

## Model Training

```bash
# Train all models
python scripts/train_all.py

# Train individual models
python scripts/train_xgboost.py        # Network classifier
python scripts/train_isolation_forest.py # Anomaly detector
python scripts/train_codebert.py        # Code vulnerability classifier
python scripts/train_codet5.py          # Fix generator
```

## Evaluation

```bash
python scripts/evaluate_xgboost.py      # NIDS metrics
python scripts/evaluate_code_classifier.py # SAST metrics
python scripts/ablation_sast.py         # SAST ablation study
python scripts/ablation_nids.py         # NIDS ablation study
```

## Testing

Unit tests are provided for the rule-based SAST classifier, the DAST active
scanner, and the triage engine, with coverage thresholds enforced in CI.

```bash
# Python: rule classifier + active scanner (requires: pip install -r requirements-dev.txt)
python -m pytest backend/services/code/tests backend/services/dast/tests

# Gateway + shared triage engine (Jest)
cd backend/gateway && npm install && npm test

# Triage engine only, with coverage
cd backend/gateway && npm run test:triage
```

## Auto-Fix & Pull Requests

The dashboard's **Repository Scanner** lets you one-click auto-fix a finding and
open a GitHub pull request for it. When you click "Auto-Fix & Create PR", the
gateway:

1. Looks up the finding and its stored `suggested_fix` (generated by the CodeT5
   fix model during the scan).
2. If no stored fix exists, asks the Code Service for a fresh fix.
3. Verifies the file exists on GitHub, creates a branch off the default branch,
   commits the fix (via the GitHub Contents API — no local clone), and opens a
   pull request with an AI-generated description and disclaimer.
4. If no reusable fix can be produced, it falls back to a **report-only
   GitHub issue** with remediation steps instead of a PR.

### Security model
- The endpoint **rejects any client-supplied code**. Fixes always come from the
  stored model output or a fresh CodeT5 call — a user cannot inject arbitrary
  code into your repository through this endpoint.
- Every attempt is **rate-limited** (5 PRs/hour) and **audit-logged** to the
  `auto_fix_logs` collection (finding, job, PR/issue URL, IP, status).
- **Fixes are AI-generated** — the generated PR/issue clearly states this and
  must be reviewed before merging.

### Setup

Add a personal access token with `repo` scope to your `.env`
(create one at https://github.com/settings/tokens):

```
GITHUB_TOKEN=ghp_your_personal_access_token
AUTO_FIX_ENABLED=true      # set to false to disable the feature
MAX_AUTO_FIX_DAILY=50      # cap on PRs/issues per IP per rolling 24h
```

The same token is also used to authenticate repository cloning during scans.
When `GITHUB_TOKEN` is missing, the auto-fix endpoint returns `503`. Set
`AUTO_FIX_ENABLED=false` to fully disable the feature for security-critical
repositories.

### API

- `POST /api/code/scan-repo/:jobId/fix` — body `{ "finding_id": "<event id>" }`.
  See the interactive docs at `http://localhost:3000/api-docs`.

## 📊 Reports & Notifications

Turn scan findings into shareable **PDF reports** and **Slack / email alerts**.
The dashboard's **Repository Scanner** page adds a toolbar to generate a report
for the current scan job and send a summary to your team.

### Generate a PDF report

`POST /api/reports/generate` aggregates findings (repo scan, DAST, or NIDS) for
a scan **job** or an optional **time range** into a PDF that includes:

- A severity distribution **bar chart** and total/active finding counts
- The top critical/high vulnerabilities (sorted by severity, then confidence)
- Per-finding detail with **CWE/OWASP** references, severity, and prediction
- **Suggested fixes** (when available) — toggle with `include_fixes: false`

```bash
# By scan job
curl -X POST http://localhost:3000/api/reports/generate \
  -H "X-Api-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"job_id": "507f1f77bcf86cd799439011"}'

# By time range (alternative)
curl -X POST http://localhost:3000/api/reports/generate \
  -H "X-Api-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"time_range": "7d"}'
```

The response returns `report_url` (a protected download link that requires the
API key) and the JSON is also streamed to the dashboard, which fetches the PDF
as a blob so the `X-Api-Key` header is included. Reports are **rate-limited**
(5/hour) and expire after `REPORT_TTL_DAYS`; expired files and log rows are
cleaned up automatically.

### Send a notification

`POST /api/notifications/send` builds a text **and** HTML summary (severity
table + top vulnerabilities + report link) and delivers it to **Slack**, **email**,
or both. Every attempt is **audit-logged** to `notification_logs`.

```bash
curl -X POST http://localhost:3000/api/notifications/send \
  -H "X-Api-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"job_id": "507f1f77bcf86cd799439011",
       "channels": ["slack", "email"],
       "recipients": ["#security-alerts", "security@example.com"]}'
```

- **Slack** uses `SLACK_WEBHOOK_URL`; the default channel is `SLACK_CHANNEL`.
  Pass a recipient starting with `#` to override the channel.
- **Email** uses the SMTP settings below. Recipients containing `@` are taken
  from the request; otherwise `NOTIFICATION_EMAIL_RECIPIENTS` is used. Emails are
  sent individually so one failure doesn't block the others.

### Setup

Add these to your `.env`:

```
# Reports (PDF)
REPORT_STORAGE_PATH=./reports        # where generated PDFs are stored
REPORT_TTL_DAYS=7                    # how long reports are kept
# PUBLIC_REPORT_BASE_URL=https://specula.company.com   # optional absolute link

# Slack notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY
SLACK_CHANNEL=#security-alerts
NOTIFICATION_EMAIL_RECIPIENTS=security@example.com,dev@example.com

# SMTP notifications
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=alerts@example.com
SMTP_PASS=your_password
SMTP_FROM=security@specula.io
```

If `SLACK_WEBHOOK_URL`/`SMTP_HOST` are missing, the corresponding channel reports
a failure in the response (`details`) instead of throwing.

## Docker

```bash
cp .env.example .env   # then fill in MONGO_USERNAME, MONGO_PASSWORD, API_KEY
docker-compose up --build
```

Services are proxied internally over the `specula-net` bridge network. Only the
gateway (3000) and dashboard (3001) are exposed. Run
`./scripts/check-env.sh` to validate your `.env` beforehand.

## License

MIT
