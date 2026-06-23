# 🍯 Honey Cloud (Rust Edition)

> **Smart Scalable Honeypot Platform** — capture, classify, and visualise
> attack traffic across SSH, FTP, HTTP, Telnet, SMTP, and RDP using Rust, Axum,
> SQLx Postgres database connection pooling, ML threat scoring, real-time WebSockets,
> and attacker intelligence profiling.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Project Structure](#project-structure)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [API Reference](#api-reference)
6. [Attacker Profiling](#attacker-profiling)
7. [Analytics Engine](#analytics-engine)
8. [ML Threat Engine](#ml-threat-engine)
9. [MITRE ATT&CK Integration](#mitre-attck-integration)
10. [WebSocket Feed](#websocket-feed)
11. [Dashboard UI](#dashboard-ui)
12. [Honeypot Modules](#honeypot-modules)
13. [Testing & Build CLI](#testing--build-cli)
14. [Deployment](#deployment)
15. [Security Notes](#security-notes)

---

## Architecture

HoneyCloud is a unified platform written entirely in high-performance **Rust**, utilizing the **Axum** web framework and **Tokio** async runtime. Axum acts as a single web server that serves both the JSON API endpoints and the static HTML dashboard files.

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Honey Cloud                                  │
│                                                                      │
│  Browser                Rust Axum Backend           Database         │
│  ┌────────┐  HTTPS/WS  ┌──────────────────────┐  ┌──────────────┐    │
│  │Dashboard│◄──────────►│  API Layer           │  │Postgres      │    │
│  │(Static) │            │  auth · events       │  │(SQLx Pool)   │    │
│  └────────┘            │  analytics · profiles│◄─│              │    │
│                        │  ml · reports · mitre│  └──────────────┘    │
│  Honeypots             └──────┬───────────────┘                      │
│  ┌───────┐  Internal Ingest   │ Services layer                       │
│  │SSH    │──────────────►     Event Ingestion                        │
│  │FTP    │                    Profiler Engine                        │
│  │HTTP   │                    AlertService (Telegram)                │
│  │TELNET │                    Mitre ATT&CK Engine                    │
│  │SMTP   │                    Report Generation                      │
│  │RDP    │                                                           │
│  └───────┘                                                           │
│                               │                                      │
│  Attackers                    │  ML Engine                           │
│  (Internet) ──TCP──► Honeypots│  Heuristic Fallback Predictor        │
│                               │  10 semantic features                │
│  Telegram ◄─── Alerts ────────┘                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Ingest pipeline per attack event:**
```
TCP → Honeypot Task → Async Ingestion (sqlx)
                            │
              ┌─────────────┴────────────────────────────┐
              │ async                                    │
              │  IP Geo-lookup                           │
              │  Heuristic ML Evaluation                 │
              │  MITRE ATT&CK Mapping                    │
              │  DB Persistent Storage                   │
              │  Real-time WebSocket Broadcast           │
              │  Telegram & Email Notifications          │
              └──────────────────────────────────────────┘
```

---

## Project Structure

```
honeycloud/
├── docker-compose.yml                ← Production stack definition
├── docker-compose.dev.yml            ← Development overrides
├── .env.example                      ← Sample configurations
├── .env                              ← Active environment file
├── .gitignore
├── README.md
├── DEPLOYMENT.md
│
└── backend-rust/
    ├── Cargo.toml                    ← Rust project cargo manifest
    ├── Dockerfile                    ← Multi-stage lean Debian runtime image builder
    ├── static/                       ← Frontend Dashboard SPA assets (served by Axum)
    │   ├── index.html                ← Login redirector
    │   ├── login.html                ← Dashboard authentication UI
    │   ├── dashboard.html            ← Full analytics view
    │   └── trap.html                 ← HTTP honeypot landing page
    └── src/
        ├── main.rs                   ← Entry point, Axum routes, TCP server spawners
        ├── config.rs                 ← Configuration loader from env
        ├── models.rs                 ← SQLx row struct representations
        ├── db.rs                     ← Database seeder, pools, migrations run
        ├── auth.rs                   ← JWT encoding/decoding and request extractors
        ├── mitre.rs                  ← Regex-based MITRE ATT&CK technique mapper
        ├── ml.rs                     ← Semantic feature extractor and ML stubs
        ├── services.rs               ← Telegram webhooks, SMTP alerts, GeoIP
        ├── websocket.rs              ← WebSocket connection registry and broadcaster
        ├── handlers.rs               ← Axum REST endpoint handler functions
        └── honeypots.rs              ← Asynchronous background TCP honeypot workers
```

---

## Quick Start

### Prerequisites
- Docker & Docker Compose (recommended)
- OR Rust (1.75+) and PostgreSQL (15+) for local compilation

### 1. Configure the Environment
Copy the sample environment file and adjust the parameters:
```bash
cp .env.example .env
# Edit .env and supply a strong SECRET_KEY (at least 32 characters)
```

> [!WARNING]
> **Database Password Constraint:** Avoid special characters like `@`, `:`, `/`, or `?` in your `POSTGRES_PASSWORD` since it is interpolated directly into the database connection string. A password like `Ganesh@123` will result in database connection parse errors. Use alphanumeric characters or underscores instead (e.g., `Ganesh123`).

### 2. Start the Stack via Docker
Deploy the entire HoneyCloud stack in a single command:
```bash
docker compose up --build -d
```

| URL / Service | Port | Description |
|---|---|---|
| http://localhost/ | `80` | Unified Frontend Dashboard UI |
| http://localhost:8000/api/v1/ | `8000` | REST API Endpoints / WebSockets |
| http://localhost:8080/ | `8080` | Fake Web Server Honeypot |
| ssh://localhost:2222 | `2222` | SSH Honeypot (Credential Harvester) |
| ftp://localhost:2121 | `2121` | FTP Honeypot |
| telnet://localhost:2323 | `2323` | Telnet Honeypot |
| smtp://localhost:2525 | `2525` | SMTP Honeypot |
| rdp://localhost:3389 | `3389` | RDP Honeypot |

### 3. Local Cargo Build (Non-Docker)
Make sure you have a local PostgreSQL instance running and configured in your `.env`.
```bash
cd backend-rust
cargo run
```
Access the dashboard locally at `http://localhost:8000/`.

### Default Credentials
On initial startup, default accounts are seeded into the database:

| Username | Password | Role | Description |
|---|---|---|---|
| `owner` | `owner123` | Owner | Superuser (User management, configuration) |
| `admin` | `admin123` | Admin | Threat mitigation (Blocking, ML retraining) |
| `analyst` | `analyst123` | Analyst | Read-only analytics dashboard |

---

## Configuration

Settings are parsed from `.env` on boot:

| Variable | Default | Required | Description |
|---|---|---|---|
| `SECRET_KEY` | — | Yes | JWT signing key (min 32 chars) |
| `DATABASE_URL` | `postgres://honeycloud:honeycloud@localhost:5432/honeycloud` | No | PostgreSQL connection URL |
| `ENVIRONMENT` | `production` | No | `development` \| `staging` \| `production` |
| `DEBUG` | `false` | No | Verbose logs if set to `true` |
| `JWT_EXPIRATION_MINUTES` | `60` | No | JWT access token life |
| `RATE_LIMIT_PER_MINUTE` | `60` | No | Global REST endpoint request limit |
| `TELEGRAM_ALERTS_ENABLED` | `false` | No | Enable real-time notification warnings |
| `TELEGRAM_BOT_TOKEN` | — | No | Telegram HTTP Bot token |
| `TELEGRAM_CHAT_ID` | — | No | Target Chat ID channel |
| `SSH_HONEYPOT_PORT` | `2222` | No | Custom TCP Port for SSH |
| `FTP_HONEYPOT_PORT` | `2121` | No | Custom TCP Port for FTP |
| `HTTP_HONEYPOT_PORT` | `8080` | No | Custom TCP Port for HTTP |
| `TELNET_HONEYPOT_PORT` | `2323` | No | Custom TCP Port for Telnet |
| `SMTP_HONEYPOT_PORT` | `2525` | No | Custom TCP Port for SMTP |
| `RDP_HONEYPOT_PORT` | `3389` | No | Custom TCP Port for RDP |

---

## API Reference

All protected endpoints require authorization header: `Authorization: Bearer <JWT_TOKEN>`.

### Authentication
- `POST /api/v1/auth/login` - Returns JWT token (JSON credentials payload).
- `GET /api/v1/auth/me` - Details of current logged-in user.
- `POST /api/v1/auth/logout` - Revokes current JWT token (blacklists it).

### Events & Stream
- `POST /api/v1/events/ingest` - External honeypot ingestion API.
- `GET /api/v1/events` - Lists stored attack events with dynamic filtering.
- `GET /api/v1/events/ws` - WebSocket real-time connection endpoint.

### Analytics & Reports
- `GET /api/v1/analytics/summary` - Statistical card counts.
- `GET /api/v1/analytics/timeline` - Series timeline of events.
- `GET /api/v1/analytics/geo` - Geographic count of IPs.
- `GET /api/v1/analytics/heatmap` - 24x7 event matrix mapping.
- `GET /api/v1/analytics/credentials` - Top usernames, passwords, commands.
- `GET /api/v1/analytics/service-trend` - Service trend patterns.
- `POST /api/v1/reports/generate` - Creates exports (CSV/TXT).
- `GET /api/v1/reports/download` - Downloads reports with path-traversal safeguards.

### Attacker Profiles
- `GET /api/v1/profiles` - Lists profiled threat actors.
- `GET /api/v1/profiles/summary` - Risk tiers distribution.
- `GET /api/v1/profiles/:ip` - Aggregated threat logs for a specific IP.
- `POST /api/v1/profiles/:ip/block` - Blocks IP.
- `POST /api/v1/profiles/:ip/unblock` - Unblocks IP.

---

## Attacker Profiling

HoneyCloud aggregates threat history under persistent `AttackerProfile` mappings. Incoming attack streams dynamically update profiles.

### Risk Tier Formula
```
Score = (Critical Severity * 4) + (High Severity * 2) 
      + Scanner Bonus (8) + Brute Force Bonus (15) + Credential Stuffing Bonus (10)
```

- **Brute Force Detection**: $\ge 10$ events from a single IP within 60 seconds.
- **Credential Stuffing**: $\ge 5$ unique credentials attempted within 5 minutes.
- **Port Scanner**: $\ge 3$ distinct protocols targeted within 5 minutes.

---

## ML Threat Engine

HoneyCloud uses a dual-model machine learning architecture to score incident risks based on a 10-dimensional semantic feature vector:

1. `service_port` — targeted service port.
2. `username_len` — length of username.
3. `password_len` — length of password.
4. `command_len` — command string length.
5. `source_port` — client port.
6. `hour_of_day` — incident hour.
7. `dangerous_pattern_count` — count of dangerous matched string patterns.
8. `is_root_user` — boolean indicating admin/root account checks.
9. `is_anonymous_user` — boolean indicating anonymous credentials.
10. `has_command` — command presence boolean.

*Heuristic Fallback:* If model weights (`data/ml_model.onnx`, `data/rf_model.onnx`) are not loaded, HoneyCloud triggers a deterministic rule-based threat evaluation so services remain active.

---

## MITRE ATT&CK Integration

Honeypot events map to MITRE ATT&CK techniques:

- **T1110 (Brute Force)**: Multiple credentials supplied during connection.
- **T1059 (Command & Scripting Interpreter)**: Commands containing shells (`bash`, `zsh`, `cmd`, `powershell`).
- **T1003 (OS Credential Dumping)**: Reading system files (`shadow`, `passwd`, `lsass`).
- **T1046 (Network Service Discovery)**: Network scanning utilities (`nmap`, `nc`).
- **T1190 (Exploit Public-Facing Application)**: Web server path injections (`../`, `union select`).
- **T1078 (Valid Accounts)**: Logging attempts matching default administrative credentials (`root`, `admin`).

---

## WebSocket Feed

To stream events asynchronously in the frontend:
```javascript
const ws = new WebSocket(`ws://${location.host}/api/v1/events/ws`);

ws.onmessage = (event) => {
  const payload = JSON.parse(event.data);
  if (payload.type === 'new_attack') {
    console.log("New attack event caught: ", payload.data);
  }
};
```

---

## Testing & Build CLI

For compilation check and packaging:

```bash
# Verify build correctness
cargo check

# Compile release builds
cargo build --release

# Run unit tests (when added)
cargo test
```

---

## Deployment

Deploying is streamlined using the `Dockerfile` inside the `backend-rust` context. A single slim runtime layer runs the optimized binary directly.

See [DEPLOYMENT.md](file:///d:/Projects/Honey%20Cloud/DEPLOYMENT.md) for full hosting blueprints.

---

## Security Notes

1. **JWT Verification**: Handlers validate JWT authorization headers on all `/api/v1/*` paths except login and ingest.
2. **Password Cryptography**: Cryptographic password generation using adaptive `bcrypt`.
3. **Database Security**: Compile-checked database query parameterization via SQLx Postgres.
4. **Path Traversal Protection**: Secure reports folder path resolution prevents path escape attempts.
5. **No Root Privilege**: The production image runs under a dedicated, limited non-root user account (`appuser`).
