"""
HoneyCloud API – application entry point.

Responsibilities:
  1. Create FastAPI instance (create_app factory)
  2. Register CORS, rate-limiting, and exception middleware
  3. Include all API routers
  4. Lifespan: DB table creation, ML model warm-up
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.core.rate_limit import limiter

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.db.session import create_all_tables

configure_logging()
logger = get_logger(__name__)
settings = get_settings()


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s v%s [%s]", settings.APP_NAME, settings.APP_VERSION, settings.ENVIRONMENT)

    # Register all ORM models with Base before create_all
    import app.models.attack_event      # noqa: F401
    import app.models.attacker_profile  # noqa: F401
    import app.models.user              # noqa: F401
    import app.models.token_blacklist   # noqa: F401
    create_all_tables()
    logger.info("Database tables verified.")

    # Seed default users if database is empty
    from app.db.session import SessionLocal
    from app.repositories.user_repository import UserRepository
    db = SessionLocal()
    try:
        user_repo = UserRepository(db)
        # Create default admin user if it doesn't exist
        if not user_repo.get_by_username("admin"):
            user_repo.create("admin", "admin123", role="admin")
            logger.info("Created default admin user.")
        # Create default analyst user if it doesn't exist
        if not user_repo.get_by_username("analyst"):
            user_repo.create("analyst", "analyst123", role="analyst")
            logger.info("Created default analyst user.")
    finally:
        db.close()

    # Warm up ML model (loads from disk if available)
    from app.api.deps import get_ml_detector
    detector = get_ml_detector()
    logger.info("ML detector ready (trained=%s).", detector.is_ready)

    logger.info("API ready → http://localhost:8000%s", settings.API_V1_PREFIX)
    if settings.DEBUG:
        logger.info("Docs        → http://localhost:8000/docs")

    yield

    logger.info("Shutting down %s.", settings.APP_NAME)


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=f"{settings.APP_NAME} API",
        description=(
            "Smart Scalable Honeypot Platform — "
            "real-time attack ingestion, ML classification, attacker profiling, and analytics."
        ),
        version=settings.APP_VERSION,
        docs_url="/docs"  if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # ── Rate limiting ─────────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # ── Centralised exception handlers ────────────────────────────────────────
    register_exception_handlers(app)

    # ── API routes ─────────────────────────────────────────────────────────────
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # ── Health / root (no auth, no prefix) ────────────────────────────────────
    @app.get("/", include_in_schema=False)
    def root():
        return {
            "service":  settings.APP_NAME,
            "version":  settings.APP_VERSION,
            "status":   "healthy",
            "ws_feed":  f"ws://localhost:8000{settings.API_V1_PREFIX}/events/ws?token=<jwt>",
        }

    @app.get("/health", include_in_schema=False)
    def health():
        from app.core.websocket_manager import ws_manager
        return {
            "status": "healthy",
            "checks": {
                "api":        "ok",
                "db":         "ok",
                "ws_clients": ws_manager.connection_count,
            },
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )
