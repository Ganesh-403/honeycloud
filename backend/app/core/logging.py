"""
Centralized structured logging configuration.
Uses JSON-style formatting in production; human-readable in development.
"""
import logging
import sys
from typing import Any

from app.core.config import get_settings

settings = get_settings()

LOG_LEVEL = logging.DEBUG if settings.DEBUG else logging.INFO

LOG_FORMAT_DEV = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_FORMAT_PROD = "%(asctime)s | %(levelname)s | %(name)s | %(funcName)s:%(lineno)d | %(message)s"


def configure_logging() -> None:
    """
    Configure root logger once at application startup.
    Call this in app lifespan only.
    """
    fmt = LOG_FORMAT_DEV if settings.DEBUG else LOG_FORMAT_PROD

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S"))

    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    root.handlers.clear()
    root.addHandler(handler)

    # Silence noisy third-party loggers
    for noisy in ("uvicorn.access", "sqlalchemy.engine", "passlib"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Use __name__ as the name."""
    return logging.getLogger(name)
