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
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        body { margin: 0; font-family: 'Inter', sans-serif; background-color: #f4f7f6; display: flex; align-items: center; justify-content: center; height: 100vh; }
        .login-container { background: #ffffff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
        .logo { margin-bottom: 20px; font-size: 24px; font-weight: 600; color: #2c3e50; }
        .logo span { color: #3498db; }
        .subtitle { color: #7f8c8d; font-size: 14px; margin-bottom: 30px; }
        .input-group { margin-bottom: 20px; text-align: left; }
        .input-group label { display: block; font-size: 12px; color: #34495e; margin-bottom: 5px; font-weight: 600; text-transform: uppercase; }
        .input-group input { width: 100%; padding: 12px; border: 1px solid #bdc3c7; border-radius: 4px; box-sizing: border-box; font-size: 14px; transition: border-color 0.3s; }
        .input-group input:focus { border-color: #3498db; outline: none; }
        .btn { background: #3498db; color: #ffffff; padding: 12px; width: 100%; border: none; border-radius: 4px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.3s; }
        .btn:hover { background: #2980b9; }
        .footer { margin-top: 30px; font-size: 12px; color: #95a5a6; }
        .error { color: #e74c3c; font-size: 13px; margin-bottom: 15px; display: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">Global<span>Secure</span></div>
        <div class="subtitle">Authorized Personnel Only</div>
        <div class="error" id="error-msg">Invalid credentials. This attempt has been logged.</div>
        <form method="POST" action="/login">
            <div class="input-group">
                <label for="username">Username / Admin ID</label>
                <input type="text" id="username" name="username" required autocomplete="off">
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">Secure Login</button>
        </form>
        <div class="footer">
            &copy; 2026 GlobalSecure Infrastructure. All rights reserved.<br>
            Unauthorized access is strictly prohibited.
        </div>
    </div>
    <script>
        // Check for error in URL parameter to show fake error
        if(window.location.search.includes('error=1')) {
            document.getElementById('error-msg').style.display = 'block';
        }
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
