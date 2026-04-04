"""
Shared pytest fixtures for HoneyCloud test suite.

Uses an in-memory SQLite DB and a fresh FastAPI TestClient per test session.
No real network calls are made (geo-IP and Telegram are mocked).
"""
import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import MagicMock, patch

# ── Environment must be set before importing app modules ──────────────────────
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-32chars")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("TELEGRAM_ALERTS_ENABLED", "false")

from app.db.session import Base, get_db          # noqa: E402
from app.main import create_app                  # noqa: E402

# ── In-memory test DB ─────────────────────────────────────────────────────────
TEST_ENGINE = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestSession  = sessionmaker(bind=TEST_ENGINE, autocommit=False, autoflush=False)


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    import app.models.attack_event      # noqa: F401
    import app.models.attacker_profile  # noqa: F401
    Base.metadata.create_all(TEST_ENGINE)
    yield
    Base.metadata.drop_all(TEST_ENGINE)


@pytest.fixture
def db_session():
    """Fresh DB session per test, rolled back after."""
    conn = TEST_ENGINE.connect()
    trans = conn.begin()
    session = TestSession(bind=conn)
    yield session
    session.close()
    trans.rollback()
    conn.close()


@pytest.fixture(scope="session")
def client():
    """TestClient wired to the in-memory DB; geo-IP is mocked."""
    def override_get_db():
        s = TestSession()
        try:
            yield s
        finally:
            s.close()

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    with patch("app.services.geo_service.lookup_location") as mock_geo, \
         patch("app.services.geo_service.resolve_ip", side_effect=lambda ip: ip):
        from app.schemas.event import LocationInfo
        mock_geo.return_value = LocationInfo(city="TestCity", country="Testland", country_code="TT", flag="🏳")
        with TestClient(app) as c:
            yield c


@pytest.fixture(scope="session")
def auth_headers(client):
    """Admin JWT headers, cached for the session."""
    r = client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin123"})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def analyst_headers(client):
    r = client.post("/api/v1/auth/login", data={"username": "analyst", "password": "analyst123"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ── Sample payloads ───────────────────────────────────────────────────────────

SAMPLE_INGEST = {
    "service": "SSH",
    "source_ip": "1.2.3.4",
    "source_port": 54321,
    "username": "root",
    "password": "toor",
    "command": "cat /etc/shadow",
    "severity": "CRITICAL",
    "method": "COMMAND",
}
