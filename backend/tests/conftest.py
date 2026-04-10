"""
Shared pytest fixtures for HoneyCloud test suite.

Uses an in-memory SQLite DB and a fresh FastAPI TestClient per test session.
No real network calls are made (geo-IP and Telegram are mocked).
"""
import os
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

# ── Environment must be set before importing app modules ──────────────────────
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-32chars")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_honeycloud.db")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("TELEGRAM_ALERTS_ENABLED", "false")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "100000")

from app.db.session import Base, SessionLocal as TestSession, engine as TEST_ENGINE, get_db  # noqa: E402
from app.main import create_app                  # noqa: E402

# ── Shared test DB (same engine used by app background tasks) ───────────────


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    import app.models.attack_event      # noqa: F401
    import app.models.attacker_profile  # noqa: F401
    import app.models.token_blacklist   # noqa: F401
    import app.models.user              # noqa: F401

    # Ensure a clean test DB for every pytest session.
    Base.metadata.drop_all(TEST_ENGINE)
    Base.metadata.create_all(TEST_ENGINE)

    # Seed default users expected by auth-dependent tests.
    from app.repositories.user_repository import UserRepository

    seed_db = TestSession()
    try:
        user_repo = UserRepository(seed_db)
        if not user_repo.get_by_username("admin"):
            user_repo.create("admin", "admin123", role="admin")
        if not user_repo.get_by_username("analyst"):
            user_repo.create("analyst", "analyst123", role="analyst")
    finally:
        seed_db.close()

    yield
    Base.metadata.drop_all(TEST_ENGINE)

    # Remove SQLite test DB file to avoid cross-run contamination.
    try:
        os.remove("test_honeycloud.db")
    except OSError:
        pass


@pytest.fixture
def db_session(reset_db_state):
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
    app.state.limiter.enabled = False
    app.dependency_overrides[get_db] = override_get_db

    with patch("app.services.geo_service.lookup_location") as mock_geo, \
         patch("app.services.event_service.lookup_location") as mock_event_geo, \
         patch("app.services.geo_service.resolve_ip", side_effect=lambda ip: ip), \
         patch("app.services.event_service.resolve_ip", side_effect=lambda ip: ip), \
         patch("app.api.v1.events.resolve_ip", side_effect=lambda ip: ip):
        from app.schemas.event import LocationInfo
        fake_location = LocationInfo(city="TestCity", country="Testland", country_code="TT", flag="🏳")
        mock_geo.return_value = fake_location
        mock_event_geo.return_value = fake_location
        with TestClient(app) as c:
            yield c


@pytest.fixture(autouse=True)
def reset_db_state():
    """Reset DB content per test and reseed required users."""
    from app.repositories.user_repository import UserRepository

    db = TestSession()
    try:
        for table in reversed(Base.metadata.sorted_tables):
            db.execute(table.delete())
        db.commit()

        user_repo = UserRepository(db)
        user_repo.create("admin", "admin123", role="admin")
        user_repo.create("analyst", "analyst123", role="analyst")
    finally:
        db.close()


@pytest.fixture
def auth_headers(client):
    """Admin JWT headers, cached for the session."""
    r = client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin123"})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
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
