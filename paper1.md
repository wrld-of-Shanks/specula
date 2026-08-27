# Specula (HORUS): An Integrated AI-Driven Security Platform for Multi-Vector Threat Detection

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Introduction](#2-introduction)
3. [System Architecture](#3-system-architecture)
4. [Detection Engines](#4-detection-engines)
5. [Machine Learning Pipeline](#5-machine-learning-pipeline)
6. [Triage & Decision Engine](#6-triage--decision-engine)
7. [Frontend & User Interface](#7-frontend--user-interface)
8. [Deployment & Infrastructure](#8-deployment--infrastructure)
9. [Audit Report](#9-audit-report)
10. [Architecture Tree & Technology Stack](#10-architecture-tree--technology-stack)
11. [DAST Evaluation](#11-dast-evaluation)
12. [Known Limitations & Future Work](#12-known-limitations--future-work)
13. [References](#13-references)

---

## 1. Executive Summary

Specula (whose scanning suite is codenamed **HORUS**) is a containerized, multi-engine security analysis platform that unifies three distinct threat detection vectors — **Network Intrusion Detection (NIDS)**, **Static Application Security Testing (SAST)**, and **Dynamic Application Security Testing (DAST)** — behind a single API gateway and real-time dashboard. The system combines classical machine learning (XGBoost, Isolation Forest), deep learning (CodeBERT, CodeT5), rule-based analysis, and automated machine learning (TPOT) into a cohesive triage pipeline that classifies, scores, and prioritizes security findings with calibrated confidence.

**Key Results:**
- XGBoost classifier achieves **99.87% weighted F1** on NSL-KDD (KDDTrain+) with **86.70% accuracy** on the held-out KDDTest+ benchmark.
- CodeBERT fine-tuned classifier achieves **99.6% validation accuracy** across 7 vulnerability classes — measured on the synthetic training distribution; generalization to real-world codebases has not yet been evaluated.
- Isolation Forest provides unsupervised novelty detection with **9.93% false positive rate** at 0.5 contamination threshold.
- Context-aware rule engine eliminates **85% of false positives** on parameterized SQL queries.
- TPOT AutoML integration enables evolutionary search for optimal sklearn pipelines.
- DAST evaluation achieves **0.821 precision** and **0.303 recall** (F1=0.442) against independently verified ground truth on DVWA, Juice Shop, WebGoat, bWAPP, and Mutillidae (76 instances across 11 check types, check_type-level matching; stricter per-endpoint (target, endpoint, check_type) matching gives F1 0.479), outperforming OWASP ZAP 2.17.0 run in its standard unauthenticated configuration — the default setup typical of a quick external scan, with no credential injection and no browser-based crawling (P=0.328, R=0.276, F1=0.300; per-endpoint F1 0.248) — on the same targets and ground truth. All passive header check types detected correctly; only 5 false positives (4 from an over-broad `exposed_metadata` check, 1 `open_redirect`); XSS reflection detection remains at zero for both tools due to authentication and SPA limitations, and SQL injection detection is limited to WebGoat (detected by ZAP only).

---

## 2. Introduction

### 2.1 Problem Statement

Modern software systems face threats across multiple layers simultaneously: network-level intrusions, code-level vulnerabilities, and runtime application weaknesses. Existing security tools typically address these vectors in isolation, requiring security analysts to manually correlate findings across disconnected dashboards. This fragmentation leads to alert fatigue, missed correlations, and delayed incident response.

### 2.2 Design Principles

Specula is built on four core principles:

1. **Unified Detection** — A single platform correlating network, code, and runtime findings.
2. **Calibrated Confidence** — Every finding carries a certainty type (confirmed vs. inferred). NIDS and SAST findings additionally carry a machine-estimated numeric confidence score from probabilistic triage; DAST findings use qualitative certainty_type and severity without a native numeric confidence value.
3. **Novel Attack Discovery** — Unsupervised anomaly detection catches threats that signature-based systems miss.
4. **Explainability** — Every detection includes structured explanations (what, why, where, remediation) rather than opaque scores.

---

## 3. System Architecture

### 3.1 High-Level Design

The system follows a **microservices architecture** with six containers orchestrated via Docker Compose:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NGINX (port 3001)                            │
│                  Landing Page (/) + Dashboard (/dashboard)          │
│                   API Proxy (/api) + WS Proxy (/ws)                │
└───────────────┬─────────────────────────────────┬───────────────────┘
                │                                 │
                ▼                                 ▼
┌───────────────────────────┐    ┌──────────────────────────────────┐
│   API GATEWAY (port 3000) │◄───│     MongoDB (port 27017)         │
│   Node.js / Express       │    │     Collections: events,         │
│   Auth, Rate Limit, WS   │    │     authorized_targets, scan_jobs│
│   Triage Engine           │    └──────────────────────────────────┘
└───┬───────────┬───────────┘
    │           │           │
    ▼           ▼           ▼
┌────────┐ ┌────────┐ ┌────────┐
│Network │ │  Code  │ │  DAST  │
│:5001   │ │ :5002  │ │ :5003  │
│Flask   │ │ Flask  │ │ Flask  │
└────────┘ └────────┘ └────────┘
```

### 3.2 Communication Pattern

- **Inbound:** Dashboard → Nginx → Gateway (`/api/*`)
- **Outbound:** Gateway → Backend services (HTTP REST)
- **Real-time:** Gateway → Dashboard (WebSocket broadcast on `/ws`)
- **Data store:** Gateway ↔ MongoDB (Mongoose ODM)
- **Inter-service:** Gateway handles all service communication; backend services do not communicate with each other directly.

### 3.3 Request Flow

1. User submits input via `UnifiedScanner` (auto-detects code/URL/repo).
2. Nginx proxies to Gateway (`/api/network/analyze`, `/api/code/scan`, or `/api/dast/scan`).
3. Gateway authenticates (API key), rate-limits, assigns request ID.
4. Gateway forwards to appropriate backend service.
5. Backend service returns structured result.
6. Gateway runs **triage engine** — assigns severity, status, confidence tier.
7. Gateway persists event to MongoDB.
8. Gateway broadcasts event via WebSocket to all connected dashboards.

---

## 4. Detection Engines

### 4.1 Network Intrusion Detection (NIDS)

**Architecture:** Ensemble of supervised + unsupervised models.

| Component | Model | Role |
|-----------|-------|------|
| Supervised | XGBoost (multi:softprob, 23 classes) | Primary classifier |
| Unsupervised | Isolation Forest (200 estimators) | Novelty detection |
| AutoML | TPOT (genetic pipeline search) | Optional replacement for XGBoost |

**Feature space:** 41 features from NSL-KDD (3 categorical: protocol_type, service, flag; 38 numeric).

**Ensemble logic:**
```
if IF.is_anomaly AND IF.anomaly_score > 0.7:
    prediction = "novel_attack"
else:
    prediction = XGBoost.predict(features)
```

**Confidence adjustment:**
- anomaly_score > 0.9 → confidence = max(supervised_conf, 0.85)
- anomaly_score > 0.7 → confidence = max(supervised_conf, 0.7)
- anomaly_score > 0.5 → confidence = supervised_conf × 0.9

### 4.2 Static Application Security Testing (SAST)

**Three-tier detection pipeline:**

| Tier | Model | Accuracy | Purpose |
|------|-------|----------|---------|
| 1 | CodeBERT (125M params) | 99.6% (validation, synthetic corpus) | Primary classifier — 7 vulnerability classes |
| 2 | Rule-based (regex/AST) | 87.0% | Fallback + context-aware validation |
| 3 | CodeT5 (seq2seq) | BLEU-based | Fix generation with beam search |

**Vulnerability classes:** `not_vulnerable, sql_injection, xss, hardcoded_credentials, command_injection, path_traversal, insecure_deserialization`

**Note on the 99.6% figure:** this is CodeBERT's *validation* accuracy measured on a train/validation split of the synthetic `cve_dataset.csv` corpus (4,239 samples, Section 5.1). It is not a held-out test evaluation on real-world code; generalization to production codebases remains unevaluated (Section 12, limitation 2).

**Key innovation — Context-aware rules:** The rule engine distinguishes between:
```sql
-- DETECTED (concatenation):
query = "SELECT * FROM users WHERE id=" + user_input

-- EXEMPT (parameterized):
query = "SELECT * FROM users WHERE id=%s" % user_id
```
This eliminates 85% of false positives on parameterized queries.

### 4.3 Dynamic Application Security Testing (DAST)

**Two modes:**

| Mode | Checks | Certainty | Approach |
|------|--------|-----------|----------|
| Passive (8) | CSP, HSTS, X-Frame-Options, cookies, CORS, TLS, error disclosure, server banner, exposed metadata | Confirmed | Deterministic header/protocol checks |
| Active (5) | SQLi, XSS, IDOR, auth bypass, endpoint discovery | Inferred | Behavioral diff + marker injection |

**Non-destructive active scanning:**
- SQLi: Sends benign vs. injected requests, compares response behavior (not content).
- XSS: Injects unique marker strings, checks for reflection without executing payloads.
- Auth bypass: Probes common admin paths, compares HTTP status codes.

**Authorization gate:** MongoDB-backed target allowlist enforced in two places — the gateway route before dispatch, and `active_scanner.py` (`require_authorization()`) before any probe executes. Localhost always permitted. External targets are auto-authorized by the gateway on first active scan.

### 4.4 TPOT AutoML Integration

TPOT (Tree-based Pipeline Optimization Tool) uses genetic programming to search the space of sklearn-compatible pipelines. The optimization entry point is `scripts/optimize_with_tpot.py`, which runs TPOT's evolutionary search over the NSL-KDD training set (80/20 stratified split) and evaluates the winning pipeline on the held-out KDDTest+ before persisting it:

```python
tpot = TPOTClassifier(
    generations=50,
    population_size=50,
    timeout=1800,  # 30 minutes (--timeout 30)
    cv=5,
    scoring='accuracy'
)
tpot.fit(X_train, y_train)
```

The runner saves a `tpot_pipeline.pkl` bundle — fitted pipeline + `LabelEncoder` + reported metrics — into `backend/services/network/models/weights/` and also exports the pipeline as `scripts/tpot_best_pipeline.py`. At inference time the `TPOTClassifier` wrapper (`tpot_model.py`) loads the bundle, inverse-transforms the encoded prediction back to an NSL-KDD class label, and derives confidence from `predict_proba` when the pipeline exposes it.

When a pipeline is present, the network service uses it as the primary classifier (`model_used: 'tpot'`) and falls back to XGBoost only when it is unavailable. The active classifier is reported by `/health` and `/models/info` (`active_classifier`). No `tpot_pipeline.pkl` is shipped with the repository yet — it is generated by running `scripts/optimize_with_tpot.py`.

---

## 5. Machine Learning Pipeline

### 5.1 Training Data

| Dataset | Samples | Classes | Source |
|---------|---------|---------|--------|
| KDDTrain+ | 125,973 | 23 attack types + normal | NSL-KDD |
| KDDTest+ | 22,544 | 23 attack types + normal | NSL-KDD |
| CodeBERT training set | 4,239 | 7 vulnerability classes | Synthetic |
| Fixes dataset | Pairs | Vulnerable → Fixed | Synthetic |

### 5.2 Model Performance

| Model | Metric | Value |
|-------|--------|-------|
| XGBoost | Weighted F1 (KDDTrain+) | 0.9987 |
| XGBoost | Accuracy (KDDTest+) | 86.70% |
| XGBoost | Macro F1 (KDDTest+) | 0.74 |
| Isolation Forest | FP rate (normal traffic) | 9.93% |
| Isolation Forest | Detection rate (attack traffic) | 78.06% |
| CodeBERT | Validation accuracy (synthetic corpus) | 99.6% |
| Rule-based | Macro F1 | 0.852 |

*CodeBERT's 99.6% is validation accuracy on the synthetic training distribution (Table 5.1), not a held-out real-world evaluation. In contrast, the XGBoost rows are measured against the genuinely held-out KDDTest+ benchmark, which is why the two figures are not directly comparable in strength of evidence.*

### 5.3 Feature Engineering

**Network features (41):**
- Connection: `duration`, `src_bytes`, `dst_bytes`, `land`
- Content: `hot`, `num_failed_logins`, `root_shell`, `num_root`, `num_shells`
- Traffic rates: `serror_rate`, `rerror_rate`, `same_srv_rate`, `diff_srv_rate`
- Host-based: `dst_host_count`, `dst_host_srv_count`, `dst_host_same_srv_rate`

**Categorical encoding:** `pd.Categorical(codes)` — alphabetical integer codes for protocol_type (tcp/udp/icmp), service (70+ types), flag (11 states).

---

## 6. Triage & Decision Engine

The triage engine operates on two certainty tracks:

### 6.1 Probabilistic Triage (Inferred Findings)

```
confidence ≥ 0.90  →  auto_flagged  (immediate action)
0.50 ≤ confidence < 0.90  →  human_review  (analyst queue)
confidence < 0.50  →  ignored  (logged only)
```

**Severity mapping:**
- ≥ 0.95 → Critical
- ≥ 0.85 → High
- ≥ 0.70 → Medium
- < 0.70 → Low

### 6.2 Deterministic Triage (Confirmed Findings)

```
critical / high  →  auto_flagged
medium / low     →  human_review
info             →  ignored
```

No numeric confidence threshold — deterministic findings bypass probabilistic logic entirely.

---

## 7. Frontend & User Interface

### 7.1 Dashboard (React + Nginx)

| Component | Function |
|-----------|----------|
| `UnifiedScanner` | Auto-detects input type (code/URL/repo), unified scan interface |
| `ThreatFeedSidebar` | Real-time WebSocket event stream (clearable, pausable) |
| `StatsBar` | Live event counts by type and severity |
| `FindingCard` | Individual finding display with severity badge, CWE/OWASP refs, fix suggestions |
| `CodeScanner` | Dedicated code snippet scanning |
| `DastScanner` | URL-based DAST scanning with passive/active mode toggle |
| `RepoScans` | Repository scan management and progress tracking |

**Styling:** Dark cinematic "vintage banknote" aesthetic with acid-green (`#d4f000`) accent, scanline overlay, grain texture.

**Deployment:** The dashboard is served as an SPA at `/dashboard` by the shared Nginx container (which also serves the landing page at `/`). API and WebSocket URLs are same-origin relative paths (`/api`, `/ws`) proxied by Nginx to the gateway, removing the hardcoded `localhost:3000` dependency. The brand is **Specula** with the security scanner codenamed HORUS.

### 7.2 Landing Page (React + Vite)

11 components including 3D visual elements (Eye of Horus, engraved eyes banner), feature grid, metrics, process walkthrough, and testimonial section.

---

## 8. Deployment & Infrastructure

### 8.1 Container Configuration

| Service | Base Image | Port | Language |
|---------|------------|------|----------|
| Gateway | `node:20-alpine` | 3000 | Node.js / Express |
| Network | `python:3.11-slim` | 5001 | Python / Flask |
| Code | `python:3.11-slim` | 5002 | Python / Flask |
| DAST | `python:3.11-slim` | 5003 | Python / Flask |
| Dashboard | `nginx:alpine` (multi-stage) | 3001 | React / Nginx (landing + dashboard) |
| MongoDB | `mongo:7` | 27017 | — |

The dashboard image is built in two stages (landing page via Vite, dashboard via CRA) into a single Nginx container that serves the landing page at `/` and the dashboard SPA at `/dashboard`. The DAST service receives `MONGO_URI` from the compose environment (previously hardcoded to `localhost`), and both the gateway and DAST declare `depends_on` on MongoDB's `service_healthy` condition.

### 8.2 Security Controls

- **Authentication:** API key with timing-safe comparison (`crypto.timingSafeEqual`)
- **Rate limiting:** 60 req/min (default), 10 req/min (scans), 5 req/min (DAST)
- **Request IDs:** UUID v4 on every request for traceability
- **CORS:** Configurable origins via `CORS_ORIGINS` env var
- **Authorization:** MongoDB-backed DAST target allowlist

### 8.3 Model Auto-Loading

The network service auto-loads models at startup from `models/weights/`:
- `tpot_pipeline.pkl` → TPOT AutoML pipeline (primary classifier when present, optional)
- `xgboost_model.pkl` → XGBoost classifier (fallback)
- `isolation_forest.pkl` → Isolation Forest detector

`load_models()` runs at startup and is re-invoked by a `before_request` hook whenever no classifier is loaded, so the service self-heals if weights are added without a restart. A `/models/info` endpoint exposes load state and per-model metadata, and `/health` reports `active_classifier` (`tpot` or `xgboost`) alongside per-model load flags.

Previously, models required a `/train` API call before predictions were available — this bug has been fixed.

---

## 9. Audit Report

### 9.1 Security Audit

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | API key exposed in `docker-compose.yml` default value | Medium | Mitigated — overridden by `.env` in production |
| 2 | MongoDB bound to `0.0.0.0:27017` with no authentication | High | Acceptable for dev; production requires `MONGO_INITDB_ROOT_USERNAME` |
| 3 | Debug mode enabled in Flask services (`debug=True`) | Medium | Should be disabled in production |
| 4 | DAST active scanning could target arbitrary external sites | High | Mitigated — authorization gate with target allowlist |
| 5 | WebSocket endpoint has no authentication | Medium | Acceptable on localhost; production needs token auth |
| 6 | `proxy_read_timeout` was too short, causing WebSocket flapping | Low | Fixed — set to 86400s |
| 7 | Mongoose connection buffering timeout caused silent failures | High | Fixed — single shared Mongoose instance; gateway now connects in an async `start()` and fails fast (`process.exit(1)`) if MongoDB is unreachable |
| 8 | Categorical encoding inconsistency between training and inference | Medium | Known issue — training uses `pd.Categorical().codes`, inference uses manual mapping dict |

### 9.2 Code Quality Audit

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | Models not auto-loaded at startup — `/predict` fails without `/train` | High | Fixed — `load_models()` called at startup |
| 2 | Hyperparameter drift between training scripts and service wrapper | Medium | Known — pre-trained pkl is correct; service defaults are weaker |
| 3 | Two different normalization methods (percentile vs sigmoid) for IF scores | Medium | Partially fixed — service uses percentile-based |
| 4 | Training/evaluation scripts had hardcoded absolute paths | Low | Fixed — `evaluate_xgboost.py`, `train_xgboost.py`, and `train_isolation_forest.py` use relative `BASE_DIR` paths |
| 5 | DAST service hardcodes `mongodb://localhost:27017` | High | Fixed — uses `MONGO_URI` env var |
| 6 | Gateway DAST route crashes on non-JSON responses | High | Fixed — Content-Type check before `.json()` |
| 7 | No unit tests for backend Python services | Medium | Known — only gateway has Jest tests |
| 8 | Synthetic training data for CodeBERT may not generalize to real codebases | Medium | Known — pending real-world evaluation |

### 9.3 ML Model Audit

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | XGBoost 13.5% generalization gap (train 99.97% vs test 86.70%) | Medium | Expected — NSL-KDD known distribution shift |
| 2 | Rare attack classes (ftp_write, multihop, phf, rootkit) have 0% F1 on test set | Medium | Due to 1-2 test samples; not a model failure |
| 3 | Isolation Forest 9.93% FP rate may be too high for production | Medium | Contamination parameter tunable |
| 4 | TPOT wrapper integrated (`tpot_model.py`, auto-load, `/models/info`) but no pipeline generated yet | Low | Run `optimize_with_tpot.py` to produce `tpot_pipeline.pkl` and benchmark against hand-tuned XGBoost |
| 5 | CodeBERT trained on synthetic data — real-world accuracy unknown | Medium | Pending evaluation on real codebases |
| 6 | Feature engineering encoding mismatch could cause silent mispredictions | High | Known — needs alignment between `feature_engineering.py` and training scripts |

### 9.4 Infrastructure Audit

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | `.dockerignore` excludes `node_modules` but not `data/` or `models/` | Low | Context copy includes ~10MB; acceptable |
| 2 | No health check probes in `docker-compose.yml` for backend services | Medium | Partially fixed — MongoDB has a `mongosh` healthcheck with `depends_on: service_healthy` for gateway and DAST; remaining services still lack probes |
| 3 | No persistent volumes for model weights | Medium | Models rebuilt on every `docker build` |
| 4 | No log aggregation or monitoring stack | Medium | Known — production needs ELK/Prometheus |
| 5 | `version: '3.8'` in docker-compose.yml is deprecated | Low | Cosmetic — ignored by Docker |

---

## 10. Architecture Tree & Technology Stack

### 10.1 Complete Project Tree

```
Specula/
├── .dockerignore
├── .env
├── .env.example
├── .gitignore
├── audit.txt
├── docker-compose.yml
├── Dockerfile.code
├── Dockerfile.dashboard
├── Dockerfile.dast
├── Dockerfile.gateway
├── Dockerfile.network
├── README.md
├── PROJECT_REPORT.md
│
├── backend/
│   ├── gateway/                          # API Gateway (Node.js)
│   │   ├── package.json
│   │   ├── server.js                     # Express + WebSocket + Mongoose
│   │   ├── __tests__/
│   │   │   ├── helpers.js
│   │   │   ├── middleware.test.js
│   │   │   ├── triage.test.js
│   │   │   └── validation.test.js
│   │   └── routes/
│   │       ├── code.js                   # /api/code/scan
│   │       ├── dast.js                   # /api/dast/scan + auth targets
│   │       ├── events.js                 # /api/events CRUD
│   │       ├── network.js                # /api/network/analyze
│   │       ├── repoScan.js               # /api/code/scan-repo (job mgmt)
│   │       └── scanRepo.js               # Repo clone + scan orchestration
│   │
│   ├── services/
│   │   ├── code/                         # SAST Engine (Python/Flask)
│   │   │   ├── app.py                    # Flask routes: /scan, /fix, /train, /repo-scan
│   │   │   ├── repo_scanner.py           # Background repo cloning + chunked scanning
│   │   │   ├── requirements.txt
│   │   │   ├── data/
│   │   │   │   └── cwe_kb.json           # CWE knowledge base
│   │   │   ├── models/
│   │   │   │   ├── codebert_classifier.py  # CodeBERT (125M) vulnerability classifier
│   │   │   │   ├── codet5_fixer.py         # CodeT5 seq2seq fix generator
│   │   │   │   └── rule_classifier.py      # Regex/AST fallback classifier
│   │   │   └── utils/
│   │   │       └── explanation_kb.py     # Structured finding explanations
│   │   │
│   │   ├── dast/                         # DAST Engine (Python/Flask)
│   │   │   ├── app.py
│   │   │   ├── active_scanner.py         # Passive (8) + Active (5) web checks
│   │   │   └── requirements.txt
│   │   │
│   │   └── network/                      # NIDS Engine (Python/Flask)
│   │       ├── app.py                    # Flask routes: /predict, /health, /models/info
│   │       ├── requirements.txt
│   │       ├── models/
│   │       │   ├── xgboost_model.py      # XGBoost wrapper (multi:softprob)
│   │       │   ├── isolation_forest.py   # Isolation Forest wrapper
│   │       │   ├── tpot_model.py         # TPOT AutoML pipeline wrapper
│   │           │   └── weights/
│   │           │       ├── xgboost_model.pkl
│   │           │       ├── isolation_forest.pkl
│   │           │       └── tpot_pipeline.pkl (optional — generated by optimize_with_tpot.py)
│   │       └── utils/
│   │           └── feature_engineering.py  # 41-feature NSL-KDD preprocessing
│   │
│   └── shared/                           # Shared gateway utilities
│       ├── mongoose.js                   # Mongoose connection singleton
│       ├── middleware/
│       │   ├── auth.js                   # API key authentication
│       │   ├── rateLimiter.js            # Sliding window rate limiting
│       │   └── requestId.js              # UUID request tracing
│       ├── schema/
│       │   ├── authorizedTarget.js       # DAST target allowlist schema
│       │   ├── event.js                  # Security event schema
│       │   └── scanJob.js                # Repository scan job schema
│       ├── triage/
│       │   └── engine.js                 # Dual-certainty triage logic
│       └── utils/
│           ├── logger.js                 # Structured logging
│           └── validation.js             # Joi request validation
│
├── data/
│   ├── code/
│   │   ├── cve_dataset.csv               # CodeBERT training data
│   │   └── fixes_dataset.csv             # CodeT5 training pairs
│   └── network/
│       ├── KDDTrain+.csv                 # NSL-KDD training set (125,973 samples)
│       ├── KDDTrain+.txt
│       ├── KDDTest+.csv                  # NSL-KDD test set (22,544 samples)
│       └── KDDTest+.txt
│
├── docs/
│   ├── ablation_study_plan.md
│   ├── evaluation.md
│   ├── evaluation_report.md
│   └── paper_sections.md
│
├── frontend/
│   ├── dashboard/                        # Security Dashboard (React + CRA)
│   │   ├── nginx.conf                    # Routing: / → landing, /dashboard → SPA
│   │   ├── package.json
│   │   ├── public/
│   │   │   └── index.html
│   │   └── src/
│   │       ├── App.js                    # Main layout + WebSocket + scanline overlay
│   │       ├── index.js
│   │       ├── components/
│   │       │   ├── UnifiedScanner.js     # Auto-detect input type scanner
│   │       │   ├── ThreatFeedSidebar.js  # Real-time event sidebar
│   │       │   ├── ThreatFeed.js         # Standalone threat feed
│   │       │   ├── StatsBar.js           # Live event counts
│   │       │   ├── StatsPanel.js         # Aggregate statistics
│   │       │   ├── CodeScanner.js        # Code snippet scanner
│   │       │   ├── DastScanner.js        # URL/DAST scanner
│   │       │   ├── RepoScans.js          # Repo scan management
│   │       │   └── FindingCard.js        # Individual finding display
│   │       ├── services/
│   │       │   ├── api.js                # Axios client (relative URLs)
│   │       │   └── websocket.js          # WebSocket hook
│   │       └── styles/
│   │           └── index.css             # Acid-green vintage banknote theme
│   │
│   └── landing/                          # Landing Page (React + Vite)
│       ├── package.json
│       ├── index.html
│       ├── public/
│       ├── vite.config.js
│       └── src/
│           ├── main.jsx
│           ├── App.jsx
│           ├── index.css
│           └── components/
│               ├── Nav.jsx               # Navigation bar
│               ├── Hero.jsx              # Hero section with CTA
│               ├── Features.jsx          # Feature grid
│               ├── HorusModel.jsx        # Eye of Horus 3D visual
│               ├── EyeOfHorus.jsx        # SVG eye component
│               ├── EyesBanner.jsx        # Engraved eyes letterbox
│               ├── Metrics.jsx           # Model metrics display
│               ├── Process.jsx           # How-it-works steps
│               ├── Quote.jsx             # Testimonial section
│               ├── CTA.jsx               # Call-to-action
│               └── Footer.jsx            # Footer with links
│
├── scripts/
│   ├── optimize_with_tpot.py             # TPOT AutoML pipeline optimization
│   ├── train_xgboost.py                  # XGBoost training (tuned hyperparams)
│   ├── train_isolation_forest.py         # Isolation Forest training
│   ├── evaluate_xgboost.py              # Ensemble evaluation (XGBoost + IF)
│   ├── train_codebert.py                # CodeBERT fine-tuning
│   ├── train_codebert_augmented.py      # CodeBERT with data augmentation
│   ├── train_codebert_fast.py           # CodeBERT quick training
│   ├── train_codebert_ultimate.py       # CodeBERT final training
│   ├── train_codet5.py                  # CodeT5 fix generator training
│   ├── train_codet5_fast.py             # CodeT5 quick training
│   ├── train_all.py                     # Train all models
│   ├── evaluate_code_classifier.py      # Code classifier evaluation
│   ├── evaluate_dast.py                  # DAST evaluation harness (HORUS + ZAP)
│   ├── dast_eval_results/                # DAST evaluation archives (raw/results/summary)
│   ├── ablation_nids.py                 # NIDS ablation study
│   ├── ablation_sast.py                 # SAST ablation study
│   ├── generate_code_dataset.py         # Synthetic code data generator
│   ├── generate_code_dataset_large.py   # Large-scale code data generator
│   ├── generate_fixes_dataset.py        # Fix pair generator
│   ├── generate_fixes_large.py          # Large-scale fix pair generator
│   ├── prepare_network_data.py          # Network data preparation
│   ├── add_authorized_target.py         # DAST target management
│   └── start-all.sh                     # Docker Compose startup script
│
└── services/
    └── network/
        └── models/
            └── weights/
                ├── xgboost_model.pkl
                └── isolation_forest.pkl
```

### 10.2 Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| **Orchestration** | Docker Compose | 3.8 | Container orchestration |
| **Reverse Proxy** | Nginx | Alpine | Static serving, API/WS proxy |
| **API Gateway** | Node.js + Express | 20.x | Request routing, auth, triage |
| **Real-time** | WebSocket (ws) | — | Live event streaming |
| **Database** | MongoDB | 7.x | Event storage, target allowlist |
| **ODM** | Mongoose | 7.8 | Schema validation, connection mgmt |
| **Validation** | Joi | — | Request payload validation |
| **Backend Services** | Python + Flask | 3.11 / 3.0 | ML inference services |
| **ML - Supervised** | XGBoost | 2.0 | Network traffic classification |
| **ML - Unsupervised** | Isolation Forest | sklearn 1.3 | Anomaly/novelty detection |
| **ML - AutoML** | TPOT | 0.12 | Genetic pipeline optimization |
| **ML - Transformers** | CodeBERT (125M) | HuggingFace | Code vulnerability classification |
| **ML - Seq2Seq** | CodeT5 | HuggingFace | Vulnerability fix generation |
| **ML - Rules** | Custom regex/AST | — | Context-aware fallback classifier |
| **Deep Learning** | PyTorch | — | Transformer inference backend |
| **Frontend** | React | 18.x | Dashboard + landing page |
| **Bundler** | Vite / CRA | — | Landing (Vite) / Dashboard (CRA) |
| **HTTP Client** | Axios | — | API communication |
| **Styling** | Custom CSS | — | Acid-green vintage banknote theme |
| **Data** | NSL-KDD | — | KDDTrain+ / KDDTest+ |
| **Testing** | Jest | — | Gateway unit tests |
| **Scripting** | Python | 3.9–3.11 | Training, evaluation, optimization |

### 10.3 API Endpoints Summary

| Method | Endpoint | Service | Description |
|--------|----------|---------|-------------|
| `GET` | `/health` | Gateway | System health (all services + MongoDB) |
| `WS` | `/ws` | Gateway | Real-time event stream |
| `POST` | `/api/network/analyze` | Network | Classify network flow |
| `POST` | `/api/code/scan` | Code | Scan code snippet |
| `POST` | `/api/code/fix` | Code | Generate fix suggestion |
| `POST` | `/api/code/scan-repo` | Code | Start repository scan |
| `GET` | `/api/code/scan-repo` | Code | List scan jobs |
| `GET` | `/api/code/scan-repo/:id` | Code | Poll job status |
| `POST` | `/api/dast/scan` | DAST | Run passive + active scan |
| `GET` | `/api/dast/authorized-targets` | DAST | List authorized targets |
| `POST` | `/api/dast/authorized-targets` | DAST | Add authorized target |
| `DELETE` | `/api/dast/authorized-targets/:t` | DAST | Remove target |
| `GET` | `/api/events` | Gateway | Paginated event list |
| `GET` | `/api/events/stats/summary` | Gateway | Aggregated statistics |
| `GET` | `/api/events/:id` | Gateway | Single event |

---

## 11. DAST Evaluation

### 11.1 Scope and Caveats

The DAST evaluation uses manually labeled ground truth against five deliberately vulnerable web applications (DVWA, OWASP Juice Shop, OWASP WebGoat, bWAPP, and Mutillidae II). This is fundamentally different from the NIDS evaluation, which uses the NSL-KDD benchmark with 22,544 labeled test instances. Ground truth labeling for DAST is manual and does not scale the way benchmark datasets do — each target requires per-endpoint security knowledge to annotate correctly. The total ground truth is 76 labeled vulnerability instances across 5 targets and 11 distinct check types. This is a small-n evaluation by design: it measures detection capability against known-vulnerable applications, not statistical generalization across a population.

Additionally, the matching methodology is coarse. The primary `compute_metrics()` matches at the **check_type level** (did HORUS find any `sqli_indicator` anywhere on the target?) rather than per-endpoint (did it find the specific SQLi at `/vulnerabilities/sqli/?id=1`?). This is an easier bar than per-instance scoring and inflates both precision and recall relative to what per-endpoint evaluation would produce. We therefore report **both** granularities: check_type-level as the primary metric and per-endpoint (target, endpoint, check_type) matching side by side (Section 11.3). The choice of primary metric is explicit: with only 76 ground-truth instances across 5 targets, per-endpoint matching would further reduce an already small sample. We report both so the reader can assess accordingly.

**Post-hoc ground truth correction.** The initial ground truth (defined before running HORUS) included 12 check types. After the first evaluation run, two categories — `exposed_metadata` and `weak_tls` — were added post-hoc because HORUS reported them and manual inspection suggested they were real findings. This introduced circularity: ground truth was adjusted based on the tool's own output. To correct this, all ground truth entries were independently verified by inspecting raw HTTP response headers (`curl -sI`) and TLS configuration, without reference to HORUS's output. This verification process (detailed in Section 11.2) resulted in: (a) removal of `exposed_metadata` from all targets (no `X-Powered-By` or equivalent implementation-detail headers confirmed), (b) removal of `missing_xfo` from Juice Shop (`X-Frame-Options: SAMEORIGIN` is present), (c) removal of `server_banner_disclosure` from Juice Shop and WebGoat (no `Server` header confirmed), and (d) removal of `insecure_cookies` from Juice Shop (JWT-based auth, no session cookies) and WebGoat (cookies set after login, not verifiable without credentials). The final ground truth reflects what is independently verifiable about each target, not what HORUS reported.

### 11.2 Methodology

Five deliberately vulnerable web applications were deployed as Docker containers:

| Target | Type | GT Labels | Verification Method |
|--------|------|-----------|---------------------|
| DVWA | PHP/MySQL | 14 | Raw headers (curl -sI) + documented CVEs |
| Juice Shop | Node.js/Angular | 15 | Raw headers (curl -sI) + documented CVEs |
| WebGoat | Java/Tomcat | 15 | Raw headers (curl -sI) + documented CVEs |
| bWAPP | PHP/MySQL | 16 | Raw headers (curl -sI) + documented CVEs |
| Mutillidae | PHP/MySQL | 16 | Raw headers (curl -sI) + documented CVEs |

**Ground truth verification evidence (raw headers):**

DVWA (`curl -sI http://localhost:4280/`):
```
Server: Apache/2.4.25 (Debian)              ← server_banner_disclosure confirmed
Set-Cookie: PHPSESSID=...; path=/           ← insecure_cookies confirmed (no HttpOnly/Secure/SameSite)
[no Content-Security-Policy]                 ← missing_csp confirmed
[no X-Frame-Options]                        ← missing_xfo confirmed
[no Strict-Transport-Security]              ← missing_hsts confirmed
HTTPS: empty response                       ← weak_tls confirmed (HTTP-only)
```

Juice Shop (`curl -sI http://localhost:3999/`):
```
[no Server header]                          ← server_banner_disclosure NOT confirmed (removed from GT)
X-Frame-Options: SAMEORIGIN                 ← missing_xfo NOT confirmed (removed from GT)
[no Content-Security-Policy]                 ← missing_csp confirmed
[no Strict-Transport-Security]              ← missing_hsts confirmed
[no X-Powered-By]                           ← exposed_metadata NOT confirmed (removed from GT)
HTTPS: empty response                       ← weak_tls confirmed (HTTP-only)
/robots.txt → Disallow: /ftp                ← exposed_path confirmed
```

WebGoat (`curl -sI http://localhost:8082/WebGoat/login`):
```
[no Server header]                          ← server_banner_disclosure NOT confirmed (removed from GT)
[no X-Frame-Options]                        ← missing_xfo confirmed
[no Content-Security-Policy]                 ← missing_csp confirmed
[no Strict-Transport-Security]              ← missing_hsts confirmed
[no X-Powered-By]                           ← exposed_metadata NOT confirmed (removed from GT)
HTTPS: empty response                       ← weak_tls confirmed (HTTP-only)
```

bWAPP (`curl -sI http://localhost:4281/login.php`):
```
Server: Apache/2.4.7 (Ubuntu)               ← server_banner_disclosure confirmed
X-Powered-By: PHP/5.5.9-1ubuntu4.14         ← server_banner_disclosure confirmed
Set-Cookie: PHPSESSID=...; path=/           ← insecure_cookies confirmed (no HttpOnly/Secure/SameSite)
[no Content-Security-Policy]                 ← missing_csp confirmed
[no X-Frame-Options]                        ← missing_xfo confirmed
[no Strict-Transport-Security]              ← missing_hsts confirmed
HTTPS: empty response                       ← weak_tls confirmed (HTTP-only)
```

Mutillidae (`curl -sI http://localhost:4282/index.php`):
```
Server: Apache/2.4.7 (Ubuntu)               ← server_banner_disclosure confirmed
X-Powered-By: PHP/5.5.9-1ubuntu4.25         ← server_banner_disclosure confirmed
Set-Cookie: PHPSESSID=...; path=/           ← insecure_cookies confirmed (no HttpOnly/Secure/SameSite)
Set-Cookie: showhints=...; path=/           ← insecure_cookies confirmed
[no Content-Security-Policy]                 ← missing_csp confirmed
[no X-Frame-Options]                        ← missing_xfo confirmed
[no Strict-Transport-Security]              ← missing_hsts confirmed
HTTPS: empty response                       ← weak_tls confirmed (HTTP-only)
```

Labels span 11 check types: `missing_csp`, `missing_xfo`, `missing_hsts`, `server_banner_disclosure`, `insecure_cookies`, `sqli_indicator`, `xss_reflection`, `exposed_path`, `error_disclosure`, `idor_indicator`, and `weak_tls`. Of the 76 entries, 13 carry explicit `header-verified` annotations (the bWAPP and Mutillidae header labels), 33 carry `documented` annotations (based on published CVEs and require application interaction to test — authentication, injection payloads), and the remaining 30 (the original three-target set) were independently verified by raw-header inspection per Section 11.1, with header labels marked "(confirmed)" in their descriptions.

Metrics use standard information retrieval definitions with check_type-level matching:

| Metric | Formula | Matching |
|--------|---------|----------|
| Precision | TP / (TP + FP) | check_type present in both GT and findings |
| Recall | TP / (TP + FN) | check_type present in GT but absent from findings |
| F1 Score | 2 × P × R / (P + R) | harmonic mean |

**Confidence scoring note:** HORUS's DAST engine produces qualitative certainty types (`confirmed`) and severity levels (`info`, `medium`, `high`) but no native numeric confidence score. The evaluation harness derives a binary confidence proxy (1.0 for `confirmed`, 0.5 otherwise) from `certainty_type` for downstream consumption. This is not a calibrated probability — unlike the NIDS triage engine (Section 6.1), which produces continuous confidence scores from XGBoost/Isolation Forest probabilities.

### 11.3 Results: HORUS vs OWASP ZAP

To contextualize HORUS's detection capability, we compared against OWASP ZAP 2.17.0 run in its **standard unauthenticated configuration — the default setup typical of a quick external scan**: out-of-box spider, passive scan, and active scan, with no credential/authentication injection and no browser-based (Ajax) crawling. ZAP was executed natively on macOS (Java 17). We deliberately did not tune ZAP (no authenticated sessions, no custom scan policies, no browser driver) because that configuration represents the practical baseline a security team receives from an external scan of a login-gated or SPA application. The same deduplication-by-check-type logic was applied to both tools' outputs.

**HORUS results (findings deduplicated by check_type before metric computation; see Section 11.6):**

| Target | GT | Findings | TP | FP | FN | Precision | Recall | F1 | Scan Time |
|--------|----|----------|----|----|----|-----------|--------|----|-----------|
| DVWA | 14 | 6 | 5 | 1 | 9 | 0.833 | 0.357 | 0.500 | 0.3s |
| Juice Shop | 15 | 4 | 3 | 1 | 12 | 0.750 | 0.200 | 0.316 | 0.7s |
| WebGoat | 15 | 5 | 4 | 1 | 11 | 0.800 | 0.267 | 0.400 | 1.6s |
| bWAPP | 16 | 6 | 5 | 1 | 11 | 0.833 | 0.312 | 0.455 | 0.6s |
| Mutillidae | 16 | 7 | 6 | 1 | 10 | 0.857 | 0.375 | 0.522 | 0.3s |
| **Aggregate** | **76** | **28** | **23** | **5** | **53** | **0.821** | **0.303** | **0.442** | **0.3–1.6s** |

**ZAP results (standard unauthenticated configuration — default spider + passive + active scan):**

| Target | GT | Findings | TP | FP | FN | Precision | Recall | F1 | Scan Time |
|--------|----|----------|----|----|----|-----------|--------|----|-----------|
| DVWA | 14 | 10 | 4 | 6 | 10 | 0.400 | 0.286 | 0.333 | 25.8s |
| Juice Shop | 15 | 4 | 1 | 3 | 14 | 0.250 | 0.067 | 0.105 | 3111.7s |
| WebGoat | 15 | 11 | 6 | 5 | 9 | 0.429 | 0.400 | 0.414 | 158.6s |
| bWAPP | 16 | 12 | 5 | 7 | 11 | 0.417 | 0.312 | 0.357 | 74.2s |
| Mutillidae | 16 | 24 | 5 | 19 | 11 | 0.208 | 0.312 | 0.250 | 3131.3s |
| **Aggregate** | **76** | **61** | **21** | **43** | **55** | **0.328** | **0.276** | **0.300** | **26s–3112s** |

**Per-endpoint matching (target, endpoint, check_type).** The tables above match at the check_type level, which counts every labeled ground-truth *instance* (e.g., WebGoat's four SQLi lessons are four instances). The same findings were re-scored at the stricter endpoint level, where the unit is the unique *(target, endpoint, check_type)* triple: findings must occur at the labeled endpoint (site-wide checks use `/`), and ground-truth instances sharing an endpoint collapse to one unit. The 76 instances reduce to 68 unique endpoint units; WebGoat collapses 15 → 8 because all its lessons POST to the same `/WebGoat/attack` URL and are distinguished only by the `lesson` parameter. Computed by `scripts/endpoint_matching.py` (`dast_eval_results/evaluation_summary_endpoint.json`), archive: `scripts/dast_eval_results/evaluation_summary_endpoint.json`.

**HORUS — check_type-level vs per-endpoint (P / R / F1):**

| Target | GT inst. | GT units | check_type | per-endpoint |
|--------|----------|----------|------------|--------------|
| DVWA | 14 | 14 | 0.833 / 0.357 / 0.500 | 0.833 / 0.357 / 0.500 |
| Juice Shop | 15 | 14 | 0.750 / 0.200 / 0.316 | 0.750 / 0.214 / 0.333 |
| WebGoat | 15 | 8 | 0.800 / 0.267 / 0.400 | 0.800 / 0.500 / 0.615 |
| bWAPP | 16 | 16 | 0.833 / 0.312 / 0.455 | 0.833 / 0.312 / 0.455 |
| Mutillidae | 16 | 16 | 0.857 / 0.375 / 0.522 | 0.857 / 0.375 / 0.522 |
| **Aggregate** | **76** | **68** | **0.821 / 0.303 / 0.442** | **0.821 / 0.338 / 0.479** |

**ZAP — check_type-level vs per-endpoint (P / R / F1):**

| Target | GT inst. | GT units | check_type | per-endpoint |
|--------|----------|----------|------------|--------------|
| DVWA | 14 | 14 | 0.400 / 0.286 / 0.333 | 0.400 / 0.286 / 0.333 |
| Juice Shop | 15 | 14 | 0.250 / 0.067 / 0.105 | 0.250 / 0.071 / 0.111 |
| WebGoat | 15 | 8 | 0.429 / 0.400 / 0.414 | 0.182 / 0.250 / 0.210 |
| bWAPP | 16 | 16 | 0.417 / 0.312 / 0.357 | 0.417 / 0.312 / 0.357 |
| Mutillidae | 16 | 16 | 0.208 / 0.312 / 0.250 | 0.167 / 0.250 / 0.200 |
| **Aggregate** | **76** | **68** | **0.328 / 0.276 / 0.300** | **0.262 / 0.235 / 0.248** |

Two observations. First, for targets whose ground truth is dominated by site-wide header checks (DVWA, bWAPP, Mutillidae, Juice Shop), the two granularities agree closely — findings and labels both sit at `/`. Second, WebGoat moves in opposite directions for the two tools, and both effects are informative. HORUS's per-endpoint F1 *rises* (0.400 → 0.615): its four header findings cover four of the eight endpoint units, and the 11 lesson-based instances that were separate check_type-level FNs collapse into four same-endpoint units. ZAP's per-endpoint F1 *falls* (0.414 → 0.210): its genuine SQL injection alert fired at `/WebGoat/register.mvc` — a real injection at a *different* URL than the lesson ground truth (`/WebGoat/attack`) — so under endpoint matching it no longer counts as a true positive, becoming both an FP (finding at an unlabeled endpoint) and an FN (labeled endpoint unmatched). The Mutillidae ZAP row drops similarly (0.250 → 0.200) because its `error_disclosure` alert fired at `/includes/` while the label names `/php-errors.php`. At the stricter granularity, HORUS retains its precision advantage (0.821 vs 0.262) with aggregate F1 0.479 vs 0.248; the per-endpoint comparison does not change the qualitative conclusions.

### 11.4 Per-Finding Breakdown

**True positives (23 instances across 6 check types):**
- `missing_csp` — Content-Security-Policy header absent (all 5 targets)
- `missing_hsts` — Strict-Transport-Security header absent (all 5 targets)
- `weak_tls` — No TLS on HTTP-only deployment (all 5 targets)
- `missing_xfo` — X-Frame-Options header absent (DVWA, WebGoat, bWAPP, Mutillidae)
- `server_banner_disclosure` — Server version leaked in HTTP headers (DVWA, bWAPP, Mutillidae)
- `insecure_cookies` — Session cookie missing security flags (Mutillidae; PHPSESSID without Secure/HttpOnly)

**False positives (5 findings):**
- `exposed_metadata` (4 findings) — The `check_exposed_metadata` function (`app.py:406`) tests three sensitive paths (`/.git/config`, `/.env`, `/robots.txt`) and flags any that return HTTP 200 with a substring indicator in the body. All 4 arise from three mechanisms.
  1. **`.env` indicator too broad** (Juice Shop `/`): The `.env` indicator is `=` (line 410), which matches virtually any HTML page. Juice Shop is an SPA that returns its HTML shell for unknown paths; the `=` characters in HTML attributes satisfy the indicator. No actual `.env` file is exposed.
  2. **Vocabulary mismatch on `/robots.txt`** (DVWA, bWAPP): Both targets serve a real `/robots.txt` file (`Disallow: /`). HORUS classifies this as `exposed_metadata`, but the ground truth labels robots.txt exposure as `exposed_path` (Juice Shop) or has no equivalent label. Same underlying fact, different check type — counts as FP for `exposed_metadata` and FN for `exposed_path` under check_type-level matching.
  3. **`/.git/config` served by Mutillidae** — Mutillidae serves a real `/.git/config` at HTTP 200; the file is the git repository metadata bundled with the vulnerable app image. It is a genuine metadata exposure but has no matching ground-truth check type (no `exposed_metadata` GT category), so it counts as FP under strict matching.
- `open_redirect` (1 finding, WebGoat) — HORUS's open-redirect probe (`app.py:430`) flags the `next` parameter accepted by WebGoat's redirect endpoint (`/WebGoat/attack?next=...`). This is a real open redirect with no corresponding ground-truth entry.

**False negatives (53 missed check types):**
- `sqli_indicator` (16) — SQL injection endpoints (all 5 targets)
- `xss_reflection` (15) — Cross-site scripting reflection points (all 5 targets)
- `error_disclosure` (8) — Error messages on malformed input (all 5 targets)
- `idor_indicator` (8) — Insecure direct object references (Juice Shop, WebGoat, bWAPP, Mutillidae)
- `exposed_path` (4) — Discoverable admin/api paths (Juice Shop 3, Mutillidae 1)
- `insecure_cookies` (2) — DVWA, bWAPP (HORUS detects this only on Mutillidae; the DVWA/bWAPP session cookies are set over HTTP without flags but HORUS's cookie check only fires when the cookie is observed with an additional distinguishing condition such as a missing `HttpOnly`)

### 11.5 Analysis

**HORUS vs ZAP comparison.** Against the standard unauthenticated ZAP configuration, HORUS outperforms ZAP in precision (0.821 vs 0.328) with a narrower recall edge (0.303 vs 0.276), yielding an aggregate F1 of 0.442 vs 0.300. HORUS also completes scans orders of magnitude faster (~0.3–1.6s vs 26s–3112s per target), though this reflects the fundamentally different scan approaches: HORUS performs targeted passive header analysis plus limited active probes, while ZAP performs full spider + passive scan + active scan with injection payloads. ZAP's scan times on the two large PHP targets dominated the range — its active scan of Juice Shop took 3111.7s and Mutillidae 3131.3s, both hitting the harness's active-scan polling cap (600 polls × 5s) before reaching completion, with raw alert collections truncated at the 2000-alert ceiling (302 raw alerts on bWAPP, 2000 on Mutillidae). These results reflect ZAP's default, out-of-box behavior; a tuned ZAP deployment (authenticated sessions, browser-based crawling) would be expected to detect more of the login-gated and SPA injection ground truth (Section 12, limitation 9).

**What each tool catches.** Both tools detect the same core header misconfigurations: `missing_csp`, `missing_xfo`, and `server_banner_disclosure`. HORUS additionally detects `missing_hsts` and `weak_tls` on all targets (ZAP has no matching alert type for either). ZAP additionally detects `insecure_cookies` (DVWA, bWAPP, WebGoat, Mutillidae) and `error_disclosure` (bWAPP, Mutillidae). For injection categories, neither tool detects `xss_reflection` on any target; `sqli_indicator` is detected only by ZAP on WebGoat (a genuine active-scan SQL injection alert against an unauthenticated lesson endpoint).

**ZAP's false positives.** ZAP's 43 aggregate false positives come from informational findings not present in the ground truth: session/auth markers (`zap_10111` Authentication Request Detected, `zap_10112` Session Management Response Identified, `zap_10109` Modern Web Application), `user_agent_fuzzer` (`zap_10104`), `timestamp_disclosure` (Unix timestamps in responses), `cross_domain` (cross-domain resource loading), `cors_misconfiguration`, `info_disclosure` (in-page banner leak), `missing_xcto` (X-Content-Type-Options absent), plus a long tail of active-scan artifacts (`zap_0`, `zap_10003`, `zap_10019`, `zap_10028`, `zap_10031`, `zap_10033`, `zap_10041`, `zap_10202`, `zap_2`, `zap_40042`, `zap_90003`, `zap_90030`) concentrated on the large PHP targets. These are valid findings in a broader security audit but do not correspond to the labeled ground truth categories in this evaluation.

**Why HORUS outperforms on this setup.** The difference is primarily structural: HORUS's header analysis checks 6 header/config categories (CSP, XFO, HSTS, Server, TLS, cookies) while ZAP's passive scan covers a similar but slightly different set (CSP, XFO, X-Content-Type-Options, cookies, server). HORUS additionally includes the `exposed_metadata`, `weak_tls`, and `open_redirect` active probes. ZAP's spider discovers more URLs, but this produces more noise (informational alerts) without improving recall on the labeled categories — hence the large F1 gap, which is driven almost entirely by precision (0.821 vs 0.328); recall is similar because both tools fail on the injection and IDOR ground truth.

**What does not work (both tools):** Neither tool detects `xss_reflection` on any of the five targets (15 ground-truth instances), nor `idor_indicator` (8 instances). SQL injection (`sqli_indicator`, 16 instances) is detected only on WebGoat by ZAP; the remaining 12 instances across DVWA, Juice Shop, bWAPP, and Mutillidae are missed by both tools. Three root causes:

1. **No authenticated crawling.** DVWA's injection endpoints require login; without session cookies neither tool can reach `/vulnerabilities/sqli/`, `/vulnerabilities/xss_r/`, or any authenticated path. ZAP's spider finds the login page but cannot progress without credentials. (bWAPP and Mutillidae expose some unauthenticated injection pages, but their forms POST session-gated parameters and error markers are suppressed on the default security level.)

2. **SPA endpoint invisibility.** Juice Shop is an Angular SPA. Its vulnerable endpoints (`/rest/products/search`, `/api/Feedbacks/{id}`) are loaded dynamically via JavaScript, not present as `<a href>` links. Neither tool's HTML parser discovers them. ZAP has an Ajax Spider extension but it requires a browser driver (Selenium/Firefox) which was not available in this headless evaluation environment.

3. **Injection detection thresholds.** Both tools' SQLi checks require either a database error marker or a response-length delta. DVWA's SQLi endpoints return consistent page sizes and suppress error messages. XSS detection requires raw `<tag>` markers in responses, but most reflection points apply HTML encoding.

**Sample size caveat:** The aggregate F1 of 0.442 (HORUS) and 0.300 (ZAP) are derived from 76 ground-truth instances across 5 targets and 11 check types. This measures detection capability on specific known-vulnerable applications, not generalization. A production DAST evaluation would require hundreds of targets with per-endpoint labeled ground truth — a significantly larger effort than this study scope.

### 11.6 Evaluation Infrastructure

- **Targets:** Docker containers (`vulnerables/web-dvwa:latest`, `bkimminich/juice-shop:latest`, `webgoat/webgoat:latest`, `raesene/bwapp:latest`, `citizenstig/nowasp:latest` [Mutillidae II]); bWAPP and Mutillidae run as amd64 images under Rosetta emulation on macOS
- **Network:** DAST service container reaching targets via Docker's `host.docker.internal` bridge; ZAP running natively on host (Java 17, OpenJDK 17.0.19)
- **Reproducibility:** `scripts/evaluate_dast.py` with `--target dvwa|juice_shop|webgoat|bwapp|mutillidae|all`, `--horus-only`, and `--zap-only` flags
- **Result archives:** The Section 11.3 figures correspond to the 2026-07-31 five-target run: HORUS + ZAP results per target in `scripts/dast_eval_results/{target}_results.json` (ZAP raw alerts in `{target}_zap_raw.json`), aggregated in `evaluation_summary.json` (HORUS TP=23/FP=5/FN=53 → P=0.821/R=0.303/F1=0.442; ZAP TP=21/FP=43/FN=55 → P=0.328/R=0.276/F1=0.300). Per-endpoint metrics are in `evaluation_summary_endpoint.json` (recomputed from the same archives by `scripts/endpoint_matching.py`). The prior 3-target run's archives remain in `*_results_old.json` (raw scans in `*_raw.json`) and match the archived deduplicated findings.
- **GT scaling run (2026-07-31):** Ground truth was expanded from 30 instances (3 targets) to 76 instances (5 targets, 11 check types) to test whether the reported metrics are artifacts of the original small corpus. bWAPP and Mutillidae contribute 16 instances each. Every new bWAPP/Mutillidae entry was verified against the running containers before labeling — confirmed absent: `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`; confirmed present: `Server: Apache/2.4.7 (Ubuntu)` and `X-Powered-By: PHP/5.5.9` banners, session cookies (`PHPSESSID`, `showhints`) without `Secure`/`HttpOnly` flags, and no HTTPS on any port. Metrics moved modestly: HORUS precision 0.800→0.821, recall 0.400→0.303 (recall drops because the expanded ground truth adds proportionally more injection/IDOR instances that neither tool can reach); ZAP F1 0.286→0.300. The qualitative conclusions — header detection is strong for both tools, injection detection fails without auth/SPA crawling, HORUS's advantage is precision — hold under GT scaling. Full run log: `/tmp/dast_eval_full.log`.
- **Zero-findings anomaly (2026-07-29) — root cause and resolution:** A harness run on 2026-07-29 recorded zero HORUS findings (`evaluation_summary.json`, HORUS tp=0 fp=0 fn=30) while ZAP produced its full alert set. Root cause: a stale native `python app.py` DAST process (started 2026-07-26) and the containerized DAST service both bound port 5003, so `localhost:5003` routing was nondeterministic between the two listeners; the native process cannot resolve Docker's `host.docker.internal` bridge hostname, so any scan routed to it silently returned zero findings. Fixes, all merged in harness commit `df3f269`: (a) terminate the stale native process; (b) add a fail-loud pre-flight probe `verify_horus_service()` that aborts the run unless the DAST service proves it can reach a `host.docker.internal` target, plus `HORUS_BASE_URL`/`WEBGOAT_PORT`/`HORUS_PROBE_URL` overrides; (c) treat a down target as fatal rather than silently dropping it from the aggregate. With all three targets running, `scripts/evaluate_dast.py --target all --horus-only` was executed 3× on 2026-07-31 (tag `dast-eval-reproducible-2026-07-31`) and reproduced the 30-instance aggregate exactly every run: TP=12, FP=3, FN=18 → P=0.800, R=0.400, F1=0.533. WebGoat was served on port 8083 during reproduction because port 8082 was occupied by an unrelated host process; findings are independent of the serving port.
- **Ground truth:** Inline definitions in `scripts/evaluate_dast.py` — 76 labeled instances across 11 check types and 5 targets (68 unique endpoint units), with per-entry verification method annotations (`header-verified`, `documented` for the bWAPP/Mutillidae additions) and an `endpoint` field per entry for per-endpoint matching
- **ZAP version:** OWASP ZAP 2.17.0 (macOS native via Homebrew cask, `brew install --cask zap`); `ZAP_TO_CHECKTYPE` mapping verified against real ZAP alert output from all 5 targets
- **ZAP scan pipeline:** Standard unauthenticated configuration typical of a quick external scan — default spider (recursive) → passive scan → active scan, no authentication injection, no Ajax Spider (browser driver unavailable in the headless evaluation environment); findings deduplicated by check_type before metric computation. HORUS findings are likewise deduplicated by check_type (the evaluation compares at the check_type level, so duplicate findings of the same type do not add information). An earlier version of the harness had two bugs in its status-polling logic: (1) it called the `action/status/` endpoint for both spider and active scan, which does not exist (returns `bad_action`); (2) the `view/status/` endpoint returns a key named `status`, but the code read `.get("progress", "100")`, silently defaulting to 100 on every poll. Both bugs caused every polling loop to exit on the first iteration, understating scan times by an order of magnitude and missing late-arriving active-scan noise alerts. The corrected harness uses `view/status/` and reads the `status` key. The figures in Section 11.3 reflect this corrected pipeline. The active-scan poll loop caps at 600 polls × 5s (3000s); scans exceeding this cap (Juice Shop, Mutillidae) proceed to alert collection with whatever has been reported so far, and raw alert collection is capped at 2000 alerts.
- **Scan time:** HORUS 0.3–1.6s per target (passive header analysis + targeted active probes); ZAP 26s–3112s per target (spider + passive + active scan cycle); the wide range reflects target complexity — Juice Shop and Mutillidae both exhausted the 3000s active-scan polling cap on time-based injection rules against undiscovered SPA routes and large PHP page sets.

---

## 12. Known Limitations & Future Work

### 12.1 Current Limitations

1. **Generalization gap:** XGBoost achieves 99.97% on training but 86.70% on test — a 13.5% gap inherent to the NSL-KDD benchmark's distribution shift.
2. **Synthetic SAST data:** CodeBERT trained on 4,239 synthetic samples may not generalize to real-world codebases without fine-tuning on actual CVEs.
3. **Categorical encoding drift:** Feature engineering uses a manual mapping dict while training scripts use `pd.Categorical().codes` — these can produce different integer encodings for the same categorical value.
4. **No persistent model storage:** Docker volumes do not persist model weights — retraining requires API calls or script execution.
5. **Single-node deployment:** No horizontal scaling, load balancing, or multi-region support.
6. **DAST active scanning gap:** Near-zero injection findings (SQLi, XSS, IDOR) across all evaluation targets — the sole exception is ZAP's SQL injection detection on WebGoat. Root cause: no authenticated crawling, SPA endpoint invisibility, and injection detection thresholds tuned for error-marker-based detection only.
7. **DAST sample size:** 76 ground-truth instances across 5 targets and 11 check types (68 unique endpoint units). Both check_type-level and per-endpoint metrics are reported (Section 11.3); the endpoint unit collapses same-URL instances — WebGoat's lesson labels all share `/WebGoat/attack` and are distinguishable only by the `lesson` parameter, which limits per-endpoint granularity there. Generalization claims require larger-scale evaluation.
8. **DAST exposed_metadata false positives:** The `check_exposed_metadata` function uses `=` as the substring indicator for `.env` files, which matches any HTML page (Juice Shop). It also classifies real `/robots.txt` files as `exposed_metadata` rather than `exposed_path`, creating vocabulary mismatches (DVWA, bWAPP). Mutillidae serves a real `/.git/config` that has no matching ground-truth check type. Total: 4 false positives across 4 targets. Fixes: use `KEY=VALUE` pattern or content-type validation for `.env`; align `exposed_metadata` and `exposed_path` check types for robots.txt.
9. **ZAP comparison scope:** The ZAP baseline was deliberately run in its standard unauthenticated configuration (default spider + passive + active scan, no credential injection, no Ajax Spider) to represent what a security team receives from a quick external scan. ZAP's full capability with browser-based crawling and authenticated sessions may close the gap on SPA and login-gated targets. A fairer head-to-head would require both tools to have equivalent access to authenticated endpoints; the reported comparison is explicitly scoped to the unauthenticated external-scan baseline.
10. **Evaluation targets are intentionally vulnerable:** All five targets (DVWA, Juice Shop, WebGoat, bWAPP, Mutillidae) are deliberately vulnerable applications. Real-world applications typically have fewer simultaneous vulnerabilities and more complex authentication flows. The relative performance gap between tools may differ on production applications.

### 12.2 Future Work

1. **TPOT pipeline generation:** The wrapper integration is complete (`tpot_model.py`, auto-load, `/models/info`); running `optimize_with_tpot.py` will produce `tpot_pipeline.pkl` for a head-to-head benchmark against hand-tuned XGBoost on KDDTest+.
2. **Real-code evaluation:** Benchmark CodeBERT on actual CVE datasets (Juliet, SARD, real GitHub advisories).
3. **Feature encoding alignment:** Unify categorical encoding between training and inference to eliminate silent misprediction risk.
4. **Production hardening:** Disable Flask debug mode, add MongoDB auth, implement WebSocket authentication, add Prometheus metrics.
5. **Ensemble expansion:** Add Random Forest, LightGBM, and neural network classifiers to the NIDS ensemble.
6. **Continuous learning:** Implement feedback loop where analyst triage decisions retrain models.
7. **DAST authenticated crawling:** Implement session-cookie-aware endpoint discovery to reach login-gated injection points (DVWA SQLi/XSS).
8. **DAST JavaScript rendering:** Add headless browser-based crawling for SPA targets (Juice Shop Angular) to discover dynamically-loaded API endpoints.
9. **DAST per-endpoint evaluation:** Per-endpoint matching is implemented (Section 11.3) but the endpoint-labeled corpus remains small (68 units) and WebGoat's lesson endpoints are not URL-distinguishable. Scale ground truth to 200+ labeled instances with distinct per-endpoint labels to produce generalizable precision/recall estimates.
10. **DAST exposed_metadata refinement:** Change the `.env` indicator from `=` to a more specific pattern (e.g., `KEY=VALUE` or content-type `text/plain`) to avoid false positives on SPA HTML responses. Add content-type validation before flagging sensitive paths.
11. **ZAP full-capability comparison:** Re-run ZAP evaluation beyond the standard unauthenticated baseline with Ajax Spider (headless browser) and authenticated scanning (form-based login injection) to compare against HORUS with equivalent target access.
12. **Multi-tool benchmark:** Extend evaluation to include other DAST tools (Burp Suite, Nuclei, Nikto) for broader comparative context.

---

## 13. References

1. Tavallaee, M., et al. "A Detailed Analysis of the KDD CUP 99 Data Set." IEEE Symposium on Computational Intelligence for Security and Defense Applications, 2009.
2. Feng, Z., et al. "CodeBERT: A Pre-Trained Model for Programming and Natural Languages." EMNLP 2020.
3. Wang, X., et al. "CodeT5: Identifier-aware Unified Pre-trained Encoder-Decoder Model for Code Understanding and Generation." EMNLP 2021.
4. Olson, R.S., et al. "Evaluation of a Tree-based Pipeline Optimization Tool for Automating Data Science." GECCO 2016.
5. Liu, F.T., et al. "Isolation Forest." IEEE International Conference on Data Mining, 2008.
6. Chen, T., & Guestrin, C. "XGBoost: A Scalable Tree Boosting System." KDD 2016.
