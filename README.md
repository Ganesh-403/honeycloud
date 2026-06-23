# 🍯 Honey Cloud

> **Smart Scalable Honeypot Platform** — capture, classify, and visualise
> attack traffic across SSH, FTP, and HTTP using FastAPI, SQLAlchemy, ML threat
> detection, real-time WebSockets, and attacker intelligence profiling.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Project Structure](#project-structure)
3. [Quick Start (5 minutes)](#quick-start)
4. [Demo Script](#demo-script)
5. [Configuration](#configuration)
6. [API Reference](#api-reference)
7. [Attacker Profiling](#attacker-profiling)
8. [Analytics Engine](#analytics-engine)
9. [ML Engine](#ml-engine)
10. [WebSocket Feed](#websocket-feed)
11. [Dashboard](#dashboard)
12. [Honeypot Modules](#honeypot-modules)
13. [Testing](#testing)
14. [Deployment](#deployment)
15. [Security Notes](#security-notes)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Honey Cloud                                  │
│                                                                      │
│  Browser                FastAPI Backend            Database          │
│  ┌────────┐  HTTPS/WS  ┌──────────────────────┐  ┌──────────────┐  │
│  │Dashboard│◄──────────►│  API Layer           │  │SQLite /      │  │
│  │(nginx) │            │  auth · events       │  │Postgres      │  │
│  └────────┘            │  analytics · profiles│◄─│              │  │
│                        │  ml · reports · mitre│  └──────────────┘  │
│  Honeypots             └──────┬───────────────┘                     │
│  ┌───────┐  POST /ingest      │ Services layer                      │
│  │SSH    │──────────────►  EventService                              │
│  │FTP    │              ProfilerService                              │
│  │HTTP   │              AlertService (Telegram)                      │
│  │TELNET │              MitreService                                 │
│  │SMTP   │              ReportService (CSV/XLSX/TXT)                 │
│  │RDP    │                                                        │
│  └───────┘                                                        │
│                               │                                     │
│  Attackers                    │  ML Engine                          │
│  (Internet) ──TCP──► Honeypots│  LSTM & Random Forest               │
│                               │  10 semantic features               │
│  Telegram ◄─── Alerts ────────┘                                    │
└──────────────────────────────────────────────────────────────────────┘
```

**Ingest pipeline per attack event:**
```
TCP → Honeypot → POST /ingest (201 ~50ms)
                      │
               ┌──────┴──────────────────────────────────┐
               │ sync                                    │ background
               │  resolve IP                             │  update AttackerProfile
               │  geo-enrich                             │  pattern detection
               │  ML classify (LSTM & RF)                │  Telegram alert
               │  MITRE ATT&CK map                       │  WebSocket broadcast
               │  DB persist                             │
               └─────────────────────────────────────────┘
```

---

## Project Structure

```
honeycloud/
├── docker-compose.yml                ← production stack
├── docker-compose.dev.yml            ← dev hot-reload overrides
├── .env.example                      ← copy → .env
├── .gitignore
├── README.md
│
├── backend/
│   ├── Dockerfile                    ← multi-stage (builder + runtime)
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── tests/
│   │   ├── conftest.py               ← fixtures, in-memory DB
│   │   ├── test_auth.py
│   │   ├── test_events.py
│   │   ├── test_analytics.py
│   │   ├── test_profiles.py
│   │   ├── test_ml.py
│   │   └── test_security.py
│   └── app/
│       ├── main.py                   ← factory, lifespan, middleware
│       ├── core/
│       │   ├── config.py             ← pydantic-settings
│       │   ├── security.py           ← JWT + bcrypt
│       │   ├── rate_limit.py         ← slowapi limiter singleton
│       │   ├── logging.py            ← structured logging
│       │   ├── exceptions.py         ← hierarchy + handlers
│       │   └── websocket_manager.py  ← WS connection registry
│       ├── api/deps.py               ← DI providers
│       ├── api/v1/
│       │   ├── router.py             ← aggregates all sub-routers
│       │   ├── auth.py               ← login (rate-limited)
│       │   ├── events.py             ← ingest · list · SSE · WebSocket
│       │   ├── analytics.py          ← 7 analytics endpoints
│       │   ├── profiles.py           ← attacker profiles + block/unblock
│       │   ├── ml.py                 ← train · status · predict
│       │   ├── mitre.py              ← MITRE ATT&CK techniques & stats
│       │   ├── stats.py
│       │   ├── reports.py
│       │   ├── simulate.py
│       │   ├── users.py              ← admin: user management (add/deactivate)
│       │   └── audit.py              ← admin: list system audit logs
│       ├── schemas/                  ← Pydantic models
│       │   └── audit.py              ← AuditLog schemas
│       ├── models/
│       │   ├── attack_event.py       ← ORM: events table
│       │   ├── attacker_profile.py   ← ORM: per-IP profiles table
│       │   ├── user.py               ← ORM: users table
│       │   ├── token_blacklist.py    ← ORM: revoked JWTs
│       │   ├── audit_log.py          ← ORM: admin action logs
│       │   ├── mitre_mapping.py      ← ORM: mitre technique mappings
│       │   └── threat_score.py       ← ORM: threat metrics table
│       ├── db/session.py
│       ├── repositories/
│       │   ├── event_repository.py
│       │   ├── profile_repository.py
│       │   ├── analytics_repository.py
│       │   ├── audit_repository.py    ← SQL queries for audit logs
│       │   └── mitre_repository.py    ← DB operations for MITRE mapping
│       ├── services/
│       │   ├── event_service.py      ← ingest pipeline + BackgroundTasks + SIEM logging
│       │   ├── profiler_service.py   ← pattern detection engine
│       │   ├── alert_service.py
│       │   ├── geo_service.py
│       │   ├── mitre_service.py      ← maps events to MITRE techniques
│       │   ├── report_service.py     ← exports CSV, Excel, PDF summaries
│       │   └── email_service.py      ← SMTP email alerting agent
│       ├── honeypots/
│       │   ├── base.py               ← BaseHoneypot ABC
│       │   ├── ssh_honeypot.py
│       │   ├── ftp_honeypot.py
│       │   ├── http_honeypot.py
│       │   ├── telnet_honeypot.py
│       │   ├── smtp_honeypot.py
│       │   └── rdp_honeypot.py
│       └── ml/
│           ├── detector.py           ← Keras LSTM wrapper
│           ├── rf_detector.py        ← Scikit-Learn Random Forest wrapper
│           └── features.py           ← 10-feature extraction pipeline
│
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    ├── index.html                    ← auth redirect
    ├── login.html                    ← login page
    └── dashboard.html                ← full analytics dashboard
```

---

## Quick Start

### Prerequisites
- Docker + Docker Compose (recommended)
- OR Python 3.11+ for local development

### 1. Clone and configure

```bash
git clone https://github.com/your-org/honeycloud.git
cd honeycloud
cp .env.example .env
# Generate a secret key with python -c "import secrets; print(secrets.token_hex(32))" and add to .env
# Review .env to set DATABASE_URL, TELEGRAM_*, rate limits, and honeypot ports.

> [!WARNING]
> **Database Password Constraint:** Do not use special characters such as `@`, `:`, `/`, or `?` in your `POSTGRES_PASSWORD`. Since this password is dynamically interpolated into the database connection URL inside `docker-compose.yml`, special characters will break connection string parsing (e.g., a password like `Ganesh@123` causes a database lookup failure for host `123@postgres`). Use alphanumeric characters and underscores instead (e.g., `Ganesh123`).
```

> Note: `SECRET_KEY` must be at least 32 characters (enforced in config).

### 2. Start the stack

```bash
docker compose up --build -d          # production  (background)
# OR
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build  # development (hot-reload, foreground)
```

| URL | Description |
|-----|-------------|
| http://localhost | Dashboard (login: `owner / owner123` or `admin / admin123`) |
| http://localhost:8000/docs | API docs (DEBUG mode only) |
| ws://localhost:8000/api/v1/events/ws?token=JWT | WebSocket feed |

### 3. Generate demo data

```bash
# Get a token first
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login -d "username=admin&password=admin123" | jq -r .access_token)
# Generate 50 demo events
curl -X POST "http://localhost:8000/api/v1/simulate?count=50" -H "Authorization: Bearer $TOKEN"
```

### 4. Train the ML model

```bash
curl -X POST http://localhost:8000/api/v1/ml/train -H "Authorization: Bearer $TOKEN"
```

### Default credentials

| Username | Password | Role | Description |
|----------|----------|------|-------------|
| `owner` | `owner123` | Owner | Superuser (full permissions + user management) |
| `admin` | `admin123` | Admin | Administrator (threat rules, block/unblock, retrain ML) |
| `analyst` | `analyst123` | Analyst | Security Analyst (read-only views) |

---

## Quick API workflow (curl examples)

1. Login and grab token:

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=admin" -d "password=admin123" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | jq -r '.access_token'
```

2. Simulate demo events:

```bash
TOKEN="$(...login command...)"
curl -X POST "http://localhost:8000/api/v1/simulate?count=30" \
  -H "Authorization: Bearer $TOKEN"
```

3. Train ML model:

```bash
curl -X POST http://localhost:8000/api/v1/ml/train \
  -H "Authorization: Bearer $TOKEN"
```

4. Check dashboard stats:

```bash
curl -X GET http://localhost:8000/api/v1/stats/ \
  -H "Authorization: Bearer $TOKEN"
```

### Troubleshooting

- `401 Unauthorized` on `/api/v1/events/ws`: JWT missing/expired or malformed query param.
- `422 Unprocessable Entity` on `/api/v1/ml/train`: need at least 50 events first (`/api/v1/simulate` helpful).
- `500` on `/api/v1/reports/generate`: ensure `REPORTS_DIR` exists and `TELEGRAM_*` config is correct when `send_telegram=true`.

---


## Configuration

All settings from `.env` (never commit `.env` to git):

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SECRET_KEY` | — | ✅ | JWT signing key (≥32 chars) |
| `DATABASE_URL` | `postgresql+psycopg2://honeycloud:change-me@postgres:5432/honeycloud` | No | SQLAlchemy URL |
| `ENVIRONMENT` | `production` | No | `development`/`staging`/`production` |
| `DEBUG` | `false` | No | Shows /docs, verbose logs |
| `ALLOWED_ORIGINS` | `["http://localhost:5173","http://localhost:80"]` | No | CORS list |
| `RATE_LIMIT_PER_MINUTE` | `60` | No | Global API rate limit |
| `TELEGRAM_ALERTS_ENABLED` | `false` | No | Telegram alert switch |
| `TELEGRAM_BOT_TOKEN` | — | No | From @BotFather |
| `TELEGRAM_CHAT_ID` | — | No | Target chat/channel |
| `SSH_HONEYPOT_PORT` | `2222` | No | |
| `FTP_HONEYPOT_PORT` | `2121` | No | |
| `HTTP_HONEYPOT_PORT` | `8080` | No | |
| `TELNET_HONEYPOT_PORT` | `2323` | No | |
| `SMTP_HONEYPOT_PORT` | `2525` | No | |
| `RDP_HONEYPOT_PORT` | `3389` | No | |

---

## API Reference

All protected routes require `Authorization: Bearer <token>` unless otherwise noted.

### Authentication
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/login` | None | Returns JWT (rate-limited 10/min) |
| GET | `/api/v1/auth/me` | Required | Current user info |
| POST | `/api/v1/auth/logout` | Required | Revoke current token (blacklist by jti) |

### Events
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/events/ingest` | None | Ingest event (honeypot agents, public, rate-limited) |
| GET | `/api/v1/events/` | Required | List with filters (limit, service, severity, time range) |
| GET | `/api/v1/events/stream` | Required | SSE real-time feed (legacy) |
| WS | `/api/v1/events/ws?token=<JWT>` | JWT param | WebSocket real-time feed (preferred) |

### Analytics
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/analytics/summary` | Required | Overview numbers |
| GET | `/api/v1/analytics/timeline?mode=hourly\|daily` | Required | Time-series |
| GET | `/api/v1/analytics/geo` | Required | Events by country |
| GET | `/api/v1/analytics/heatmap` | Required | 24×7 hour/day matrix |
| GET | `/api/v1/analytics/credentials` | Required | Top usernames, passwords, commands |
| GET | `/api/v1/analytics/service-trend` | Required | SSH/FTP/HTTP daily split |

### Attacker Profiles
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/profiles/` | Required | List profiles (filterable) |
| GET | `/api/v1/profiles/summary` | Required | Risk tier counts + top attackers |
| GET | `/api/v1/profiles/{ip}` | Required | Full profile for one IP |
| POST | `/api/v1/profiles/{ip}/block` | Admin | Block an IP |
| POST | `/api/v1/profiles/{ip}/unblock` | Admin | Remove block |

### ML Engine
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/ml/status` | Required | Models status + features (both LSTM and RF) |
| POST | `/api/v1/ml/train` | Admin | Train LSTM model on stored events |
| POST | `/api/v1/ml/predict` | Required | Single-event prediction using LSTM (debug) |
| POST | `/api/v1/ml/train-rf` | Admin | Train Random Forest model on stored events |
| POST | `/api/v1/ml/predict-rf` | Required | Single-event prediction using Random Forest (debug) |

### MITRE ATT&CK
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/mitre/techniques` | Required | List all known MITRE ATT&CK techniques |
| GET | `/api/v1/mitre/stats` | Required | Aggregated technique & tactic counts |
| GET | `/api/v1/mitre/event/{event_id}` | Required | Technique mappings for a specific event |

### Reports & Stats
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/stats/` | Required | Aggregate counts by severity/service/AI label |
| POST | `/api/v1/reports/generate?fmt=csv\|xlsx\|txt&send_telegram=true\|false` | Admin | Generate report and optionally send via Telegram |
| GET | `/api/v1/reports/download?file=name` | None | Secure file download (safe path validation) |
| POST | `/api/v1/simulate/?count=N` | Required | Generate N demo events (authenticated user) |

---

## Attacker Profiling

HoneyCloud automatically builds a persistent `AttackerProfile` for every unique
attacking IP. Profiles are updated in the background after each ingest event.

### Risk Tiers

| Tier | Weighted Score | Description |
|------|---------------|-------------|
| UNKNOWN | 0–2 | New / minimal activity |
| LOW | 2–8 | Minor probing |
| MEDIUM | 8–20 | Active scanning |
| HIGH | 20–50 | Sustained attacks |
| CRITICAL | 50+ | Severe / persistent threat |
| BLOCKED | — | Admin-blocked |

Score formula:
```
score = (critical_events × 4) + (high_events × 2)
      + brute_force_bonus(15) + credential_stuffing_bonus(10)
      + scanner_bonus(8)
```

### Pattern Detection

| Pattern | Detection Rule |
|---------|----------------|
| Brute Force | ≥ 10 events from same IP within 60 seconds |
| Credential Stuffing | ≥ 5 unique passwords from same IP within 5 minutes |
| Port Scanner | ≥ 3 distinct services from same IP within 5 minutes |

---

## MITRE ATT&CK Integration

HoneyCloud automatically maps incoming attack event signatures to known techniques under the MITRE ATT&CK matrix in the background.

### Supported Techniques

| ID | Technique Name | Tactic | Description & Mapping Rule |
|----|----------------|--------|----------------------------|
| **T1110** | Brute Force | Credential Access | Triggered when `username` and `password` are both supplied (90% confidence on SSH/FTP/TELNET/RDP, 70% otherwise). |
| **T1059** | Command & Scripting Interpreter | Execution | Triggered when matching interpreter shells (`bash`, `sh`, `zsh`, `python`, `powershell`, `cmd.exe`, etc.) or execution commands (`exec`, `eval`) in input. |
| **T1003** | OS Credential Dumping | Credential Access | Triggered when searching for credential files/utilities (`/etc/shadow`, `/etc/passwd`, `mimikatz`, `secretsdump`, `lsass`, etc.). |
| **T1046** | Network Service Discovery | Discovery | Triggered when network scanning tool names (`nmap`, `netstat`, `netcat`, `nc`, `portscan`, `traceroute`) are detected. |
| **T1190** | Exploit Public-Facing Application | Initial Access | Triggered for HTTP events that match common injection patterns (`union select`, `../`, `<script`, etc.). |
| **T1078** | Valid Accounts | Defense Evasion | Triggered when login attempts use well-known default administrative usernames (e.g., `root`, `admin`, `administrator`, `postgres`, `mysql`). |

Technique mappings are persisted to the database and can be queried for individual events or in aggregate to build tactic/technique heatmaps.

---

## Analytics Engine

7 analytics endpoints backed by optimised raw SQL queries:

- **Timeline**: hourly (24h) or daily (30 days) event counts
- **Geo distribution**: top 50 countries with event counts and unique IPs
- **Heatmap**: 24×7 matrix showing *when* attacks peak (ideal for scheduling)
- **Credential intelligence**: most-attempted usernames, passwords, and commands
- **Service trend**: SSH/FTP/HTTP daily breakdown for trend analysis

---

## ML Engine

HoneyCloud uses a dual-model machine learning architecture for real-time classification of attack severity and threat cross-verification.

### Features (10 dimensions)

Both models leverage the same 10-dimensional numeric and text feature vector extracted from incoming events:
```
service_port            – protocol port (SSH=22, FTP=21, HTTP=80, etc.)
username_len            – character length of attempted username
password_len            – character length of attempted password
command_len             – character length of command / path
source_port             – originating port
hour_of_day             – hour (0–23) from event timestamp
dangerous_pattern_count – count of matched dangerous regex patterns
is_root_user            – 1 if username in {root, admin, administrator}
is_anonymous_user       – 1 if username in {anonymous, guest, visitor}
has_command             – 1 if command/path is non-empty
```

### Models

#### 1. Primary Model: Keras LSTM
* **Type**: Deep Learning LSTM sequence classifier (evaluates command inputs sequentially).
* **Saved Model**: `data/ml_model.keras` (+ `tokenizer.pkl`).
* **Labels**:
  | Label | Condition |
  |-------|-----------|
  | `benign` | LSTM prediction score < 0.5 |
  | `malicious` | LSTM prediction score ≥ 0.5 |
  | `unknown` | Model not yet trained |

#### 2. Secondary Model: Scikit-Learn Random Forest
* **Type**: Random Forest Classifier (100 estimators) for cross-verification.
* **Saved Model**: `data/rf_model.pkl`.
* **Labels**:
  | Label | Condition |
  |-------|-----------|
  | `benign` | Low severity / threat features |
  | `suspicious` | Medium severity / scanned features |
  | `malicious` | High/Critical severity / malicious patterns |
  | `unknown` | Model not yet trained |

### Model Training & Retraining

Models are trained on stored historical events (minimum 50 required).

* **Train LSTM**:
  ```bash
  curl -X POST http://localhost:8000/api/v1/ml/train -H "Authorization: Bearer $TOKEN"
  ```
* **Train Random Forest**:
  ```bash
  curl -X POST http://localhost:8000/api/v1/ml/train-rf -H "Authorization: Bearer $TOKEN"
  ```

Models persist to `data/` and are reloaded automatically on service start.

---

## WebSocket Feed

Real-time push-based event streaming — zero polling overhead.

```javascript
// Connect
const ws = new WebSocket(`ws://localhost:8000/api/v1/events/ws?token=${jwt}`);

// Receive events
ws.onmessage = ({ data }) => {
  const msg = JSON.parse(data);
  if (msg.type === 'new_attack') {
    console.log(msg.data);  // full event object
  }
};

// Ping / connection count
ws.send(JSON.stringify({ type: 'ping' }));
// → { "type": "pong", "connections": 3 }
```

Server sends `{ "type": "heartbeat" }` every 30 seconds. Disconnected clients
reconnect automatically (dashboard retries every 4 seconds).

---

## Dashboard

Single-file SPA at `/dashboard.html` — no build step required.

| Page | Contents |
|------|----------|
| **Overview** | 6 stat cards + 4 Chart.js charts (timeline, severity, service, AI); auto-refresh 15s |
| **Live Feed** | WebSocket-powered event table; filter by service/severity; max 200 rows |
| **Analytics** | 30-day timeline, service trend, geographic top-12 bar chart |
| **Profiles** | IP risk table; block/unblock actions; click IP for full detail panel |
| **MITRE ATT&CK** | Technique and tactic breakdown charts (Chart.js) + mapped technique details list |
| **Heatmap** | 24×7 colour-gradient attack timing matrix |
| **Credentials** | Top-15 usernames, passwords, and commands with animated bar charts |

---

## Honeypot Modules

All extend `BaseHoneypot`:

```python
class BaseHoneypot(ABC):
    protocol: str          # "SSH" | "FTP" | "HTTP" | "TELNET" | "SMTP" | "RDP"

    async def start(port: int): ...
    async def stop(): ...

    # Helpers available to all subclasses:
    _build_event(source_ip, source_port, **kwargs) → dict
    _post_event(event: dict)     # fire-and-forget POST to /ingest
    _classify_command(cmd) → str # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
```

**Adding a new honeypot:**
1. Create `app/honeypots/myproto_honeypot.py` extending `BaseHoneypot`
2. Set `protocol = "MYPROTO"` and implement `start()` / `stop()`
3. Use `_build_event()` + `_post_event()` – no other changes needed
4. Register in `main.py` lifespan block

Built-in honeypots: SSH, FTP, HTTP, TELNET, SMTP, and RDP.

---

## Testing

```bash
# Install test deps
cd backend && pip install pytest httpx pytest-asyncio

# Run all tests
cd backend && pytest

# With coverage
cd backend && pytest --cov=app --cov-report=term-missing

# Quick (skips ML tests)
cd backend && pytest -k "not test_ml"
```

Test suite coverage:

| Module | Tests | Scope |
|--------|-------|-------|
| `test_auth.py` | 6 | Login, JWT, roles |
| `test_events.py` | 10 | Ingest, filters, schema, edge cases |
| `test_analytics.py` | 10 | All 7 analytics endpoints |
| `test_profiles.py` | 9 | CRUD, block/unblock, RBAC |
| `test_ml.py` | 8 | Feature extraction, train, save/load |
| `test_security.py` | 10 | Tampered tokens, path traversal, oversized payloads |

---

## Deployment

### Production checklist

- [ ] `SECRET_KEY` is a random 64-char hex
- [ ] `ENVIRONMENT=production`, `DEBUG=false`
- [ ] `ALLOWED_ORIGINS` locked to your actual domain
- [ ] Telegram token configured (or `TELEGRAM_ALERTS_ENABLED=false`)
- [ ] Honeypot ports (2222, 2121, 8080) exposed; API port (8000) internal only
- [ ] Nginx terminates TLS; backend is behind reverse proxy
- [ ] `data/` and `reports/` volumes are backed up
- [ ] Run ML training (via /api/v1/ml/train) after accumulating real traffic

### PostgreSQL Notes

PostgreSQL is the default database in `.env.example` and `docker-compose.yml` now
starts a `postgres` service automatically.

If you need SQLite for a lightweight local run, set:

```bash
DATABASE_URL=sqlite:///./data/honeycloud.db
```

---

## Security Notes

| Area | Implementation |
|------|---------------|
| Secrets | `pydantic-settings` + `.env`; none in source |
| Passwords | bcrypt via `passlib` |
| JWT | HS256, configurable expiry, validated on every request |
| Rate limiting | `slowapi` – 10/min on login, 60/min global |
| CORS | Explicit `ALLOWED_ORIGINS` (no wildcard) |
| Input validation | Pydantic field validators on all routes |
| Path traversal | `ReportService.safe_path()` uses `Path.resolve()` parent check |
| WebSocket auth | JWT validated before connection upgrade; `4001 Unauthorized` |
| Container | `USER appuser` (UID 1001) in Dockerfile |
| RBAC | `analyst` → read-only; `admin` → full including block/train/report |

---

*Built with FastAPI · SQLAlchemy · scikit-learn · asyncio · WebSockets · Chart.js · Docker*
