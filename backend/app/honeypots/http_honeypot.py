"""
HTTP Honeypot – FastAPI sub-application mounted at a separate port (8080).
Catches ALL HTTP methods on ALL paths, logs them, and returns fake 200 OK.

This completely replaces the Flask-based http_honeypot.py.
Mount it in main.py:  app.mount("/honeypot", http_honeypot_app)
Or run it standalone on a different port via its own uvicorn instance.
"""
from __future__ import annotations

import asyncio

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.logging import get_logger
from app.honeypots.base import BaseHoneypot

logger = get_logger(__name__)

# ── Fake server headers (fingerprint as Apache) ───────────────────────────────
FAKE_HEADERS = {
    "Server": "Apache/2.4.54 (Ubuntu)",
    "X-Powered-By": "PHP/8.1.2",
}


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
    async def catch_all(full_path: str, request: Request) -> JSONResponse:
        source_ip   = request.client.host if request.client else "0.0.0.0"
        source_port = request.client.port if request.client else 0
        method      = request.method
        path        = f"/{full_path}"
        user_agent  = request.headers.get("User-Agent", "")
        body        = (await request.body()).decode("utf-8", errors="ignore")[:512]

        severity = honeypot._http_severity(method, path, body, request.headers)
        command  = f"{method} {path}"

        logger.info(
            "[HTTP] %s %s | ip=%s ua=%r sev=%s",
            method, path, source_ip, user_agent[:80], severity,
        )

        honeypot._post_event(
            honeypot._build_event(
                source_ip=source_ip,
                source_port=source_port,
                method=method,
                endpoint=path,
                command=command,
                payload=body or None,
                user_agent=user_agent,
                severity=severity,
                metadata={
                    "headers": dict(request.headers),
                    "query_params": str(request.query_params),
                },
            )
        )

        # Return a plausible-looking response
        return JSONResponse(
            content={"status": "ok"},
            headers=FAKE_HEADERS,
        )

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
