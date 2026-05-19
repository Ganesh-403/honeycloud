"""
HTTP Honeypot – FastAPI sub-application mounted at a separate port (8080).
Catches ALL HTTP methods on ALL paths, logs them, and returns fake responses.
Includes a highly realistic fake login portal for capturing simulated attacks.
"""
from __future__ import annotations

import asyncio
import urllib.parse

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, Response

from app.core.logging import get_logger
from app.honeypots.base import BaseHoneypot

logger = get_logger(__name__)

# ── Fake server headers (fingerprint as Apache) ───────────────────────────────
FAKE_HEADERS = {
    "Server": "Apache/2.4.54 (Ubuntu)",
    "X-Powered-By": "PHP/8.1.2",
}

# ── Fake Login HTML Template ──────────────────────────────────────────────────
FAKE_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Secure Access Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #4F46E5;
            --secondary: #ec4899;
            --bg: #0f172a;
            --surface: rgba(30, 41, 59, 0.4);
            --border: rgba(255, 255, 255, 0.1);
            --text: #f8fafc;
            --muted: #94a3b8;
            --danger: #ef4444;
        }
        body { margin: 0; font-family: 'Inter', sans-serif; background-color: var(--bg); color: var(--text); display: flex; align-items: center; justify-content: center; height: 100vh; overflow: hidden; position: relative; }
        body::before {
            content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%;
            background: radial-gradient(circle at 50% 50%, rgba(79, 70, 229, 0.15) 0%, transparent 40%),
                        radial-gradient(circle at 80% 20%, rgba(236, 72, 153, 0.15) 0%, transparent 40%),
                        radial-gradient(circle at 20% 80%, rgba(139, 92, 246, 0.15) 0%, transparent 40%);
            animation: rotateGlow 25s linear infinite; z-index: -1;
        }
        @keyframes rotateGlow { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .login-container {
            background: var(--surface); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border); border-radius: 20px; padding: 40px; box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
            width: 100%; max-width: 400px; text-align: center; position: relative; overflow: hidden;
            animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards; opacity: 0; transform: translateY(20px);
        }
        @keyframes slideUp { to { opacity: 1; transform: translateY(0); } }
        .login-container::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
        }
        .logo { font-family: 'Outfit', sans-serif; margin-bottom: 5px; font-size: 28px; font-weight: 800; background: linear-gradient(135deg, #fff 0%, #a5b4fc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .logo span { background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: var(--muted); font-size: 12px; margin-bottom: 30px; text-transform: uppercase; letter-spacing: 0.15em; }
        .input-group { margin-bottom: 20px; text-align: left; }
        .input-group label { display: block; font-size: 11px; color: var(--muted); margin-bottom: 8px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
        .input-group input { width: 100%; background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border); border-radius: 10px; color: var(--text); padding: 14px; font-family: 'Inter', sans-serif; font-size: 14px; outline: none; transition: all 0.3s ease; box-sizing: border-box; }
        .input-group input:focus { border-color: var(--primary); background: rgba(79, 70, 229, 0.05); box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.15); }
        .btn { background: linear-gradient(135deg, var(--primary) 0%, #6366f1 100%); color: #ffffff; padding: 14px; width: 100%; border: none; border-radius: 10px; font-family: 'Outfit', sans-serif; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(79, 70, 229, 0.3); }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(79, 70, 229, 0.5); }
        .footer { margin-top: 30px; font-size: 11px; color: var(--muted); opacity: 0.7; }
        .error { color: var(--danger); font-size: 13px; margin-bottom: 15px; display: none; font-weight: 500; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">Global<span>Secure</span></div>
        <div class="subtitle">Authorized Personnel Only</div>
        <div class="error" id="error-msg">Invalid credentials. This attempt has been logged.</div>
        <form method="POST" action="/login">
            <div class="input-group">
                <label for="username">Admin ID / Username</label>
                <input type="text" id="username" name="username" required autocomplete="off" spellcheck="false">
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">Authenticate</button>
        </form>
        <div class="footer">
            &copy; 2026 GlobalSecure Infrastructure. All rights reserved.<br>
            Unauthorized access is strictly prohibited.
        </div>
    </div>
    <script>
        if(window.location.search.includes('error=1')) {
            document.getElementById('error-msg').style.display = 'block';
            const card = document.querySelector('.login-container');
            card.style.animation = 'none'; card.offsetHeight;
            card.style.animation = 'shake .35s ease-out';
        }
        const style = document.createElement('style');
        style.textContent = `@keyframes shake { 0%,100%{transform:translateX(0)} 20%{transform:translateX(-7px)} 40%{transform:translateX(7px)} 60%{transform:translateX(-5px)} 80%{transform:translateX(5px)} }`;
        document.head.appendChild(style);
    </script>
</body>
</html>
"""


def create_http_honeypot_app(honeypot: "HTTPHoneypot") -> FastAPI:
    """
    Build a FastAPI app that logs every request as a honeypot event
    and returns a convincing fake response.
    """
    app = FastAPI(
        title="HTTP Honeypot",
        docs_url=None,    # don't expose /docs on the honeypot port
        redoc_url=None,
    )

    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )
    async def catch_all(full_path: str, request: Request) -> Response:
        source_ip   = request.client.host if request.client else "0.0.0.0"
        source_port = request.client.port if request.client else 0
        method      = request.method
        path        = f"/{full_path}"
        user_agent  = request.headers.get("User-Agent", "")
        body_bytes  = await request.body()
        body        = body_bytes.decode("utf-8", errors="ignore")[:512]

        username = None
        password = None
        response: Response

        # Serve Fake Login Page
        if path in ("/", "/login") and method == "GET":
            severity = "LOW"
            command = f"GET {path}"
            response = HTMLResponse(content=FAKE_LOGIN_HTML, headers=FAKE_HEADERS)
            
        # Handle Fake Login Submissions
        elif path == "/login" and method == "POST":
            parsed_form = urllib.parse.parse_qs(body)
            username = parsed_form.get("username", [""])[0]
            password = parsed_form.get("password", [""])[0]
            
            # Check for SQL injection patterns to upgrade severity
            severity = honeypot._http_severity(method, path, body, request.headers)
            if severity in ("LOW", "MEDIUM"):
                severity = "HIGH" # Treat all explicit login attempts as at least HIGH
                
            command = f"POST /login (u:{username[:20]})"
            # Return a fake error redirect
            response = RedirectResponse(url="/?error=1", status_code=302, headers=FAKE_HEADERS)
            
        # Generic fallback for other routes
        else:
            severity = honeypot._http_severity(method, path, body, request.headers)
            command  = f"{method} {path}"
            response = JSONResponse(content={"status": "ok"}, headers=FAKE_HEADERS)

        logger.info(
            "[HTTP] %s %s | ip=%s ua=%r sev=%s",
            method, path, source_ip, user_agent[:80], severity,
        )

        event_kwargs = {
            "source_ip": source_ip,
            "source_port": source_port,
            "method": method,
            "endpoint": path,
            "command": command,
            "payload": body or None,
            "user_agent": user_agent,
            "severity": severity,
            "metadata": {
                "headers": dict(request.headers),
                "query_params": str(request.query_params),
            },
        }
        if username:
            event_kwargs["username"] = username
        if password:
            event_kwargs["password"] = password

        honeypot._post_event(
            honeypot._build_event(**event_kwargs)
        )

        return response

    return app


class HTTPHoneypot(BaseHoneypot):
    protocol = "HTTP"

    def __init__(self):
        super().__init__()
        self._server_task: asyncio.Task | None = None

    async def start(self, port: int) -> None:
        honeypot_app = create_http_honeypot_app(self)
        config = uvicorn.Config(
            honeypot_app,
            host="0.0.0.0",
            port=port,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(config)
        self._server_task = asyncio.create_task(server.serve())
        self._running = True
        logger.info("[HTTP] Honeypot listening on port %d", port)

    async def stop(self) -> None:
        if self._server_task:
            self._server_task.cancel()
            try:
                await self._server_task
            except asyncio.CancelledError:
                pass
        self._running = False
        logger.info("[HTTP] Honeypot stopped.")

    # ── Severity classification ────────────────────────────────────────────────

    @staticmethod
    def _http_severity(
        method: str,
        path: str,
        body: str,
        headers: dict,
    ) -> str:
        path_l = path.lower()
        body_l = body.lower()

        critical_paths = {
            "/etc/passwd", "/etc/shadow", "/../", "/.git",
            "/wp-admin", "/phpmyadmin", "/.env",
        }
        critical_body  = {"<script", "exec(", "eval(", "base64_decode", "union select"}

        if any(p in path_l for p in critical_paths):
            return "CRITICAL"
        if any(b in body_l for b in critical_body):
            return "CRITICAL"
        if method in ("PUT", "DELETE", "PATCH"):
            return "HIGH"
        if "/admin" in path_l or "/api" in path_l:
            return "HIGH"
        if method == "POST":
            return "MEDIUM"
        return "LOW"
