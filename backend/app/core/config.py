"""
Core configuration management using pydantic-settings.
All settings are loaded from environment variables or .env file.
"""
import os
from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "HoneyCloud"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"  # development | staging | production

    # ── API ───────────────────────────────────────────────────────────────────
    API_V1_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:80"]

    # ── Security ─────────────────────────────────────────────────────────────
    SECRET_KEY: str  # REQUIRED – no default intentionally
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite:///./honeycloud.db"

    # ── Rate limiting ────────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60

    # ── Telegram alerts ───────────────────────────────────────────────────────
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""
    TELEGRAM_ALERTS_ENABLED: bool = False

    # ── Geo-IP ────────────────────────────────────────────────────────────────
    GEOIP_TIMEOUT_SECONDS: int = 5
    ABUSEIPDB_API_KEY: str = ""

    # ── Honeypots ─────────────────────────────────────────────────────────────
    SSH_HONEYPOT_PORT: int = 2222
    FTP_HONEYPOT_PORT: int = 2121
    HTTP_HONEYPOT_PORT: int = 8080
    TELNET_HONEYPOT_PORT: int = 2323

    # ── Reports ───────────────────────────────────────────────────────────────
    REPORTS_DIR: str = "reports"

    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_must_be_strong(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long.")
        return v

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of: {allowed}")
        return v


@lru_cache()
def get_settings() -> Settings:
    """Return settings instance."""
    return Settings()
