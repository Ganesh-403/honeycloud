"""Tests for analytics endpoints."""
import pytest
from tests.conftest import SAMPLE_INGEST


@pytest.fixture(autouse=True)
def seed_events(client):
    """Create a handful of events before each test."""
    payloads = [
        {**SAMPLE_INGEST, "severity": "CRITICAL", "service": "SSH"},
        {**SAMPLE_INGEST, "severity": "HIGH",     "service": "HTTP", "source_ip": "2.2.2.2"},
        {**SAMPLE_INGEST, "severity": "LOW",      "service": "FTP",  "source_ip": "3.3.3.3",
         "username": "anonymous", "password": "anon@"},
    ]
    for p in payloads:
        client.post("/api/v1/events/ingest", json=p)


class TestAnalytics:
    def test_summary_requires_auth(self, client):
        r = client.get("/api/v1/analytics/summary")
        assert r.status_code == 401

    def test_summary_returns_fields(self, client, auth_headers):
        r = client.get("/api/v1/analytics/summary", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        for field in ("total_events", "unique_attackers", "critical_total", "malicious_total", "avg_threat_score"):
            assert field in body

    def test_summary_counts_positive(self, client, auth_headers):
        r = client.get("/api/v1/analytics/summary", headers=auth_headers)
        body = r.json()
        assert body["total_events"] > 0
        assert body["unique_attackers"] > 0

    def test_timeline_hourly(self, client, auth_headers):
        r = client.get("/api/v1/analytics/timeline?mode=hourly", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_timeline_daily(self, client, auth_headers):
        r = client.get("/api/v1/analytics/timeline?mode=daily", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_timeline_invalid_mode(self, client, auth_headers):
        r = client.get("/api/v1/analytics/timeline?mode=yearly", headers=auth_headers)
        assert r.status_code == 422

    def test_heatmap_structure(self, client, auth_headers):
        r = client.get("/api/v1/analytics/heatmap", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        if data:
            cell = data[0]
            assert "hour" in cell and "day" in cell and "count" in cell
            assert 0 <= cell["hour"] <= 23
            assert 0 <= cell["day"]  <= 6

    def test_credentials_structure(self, client, auth_headers):
        r = client.get("/api/v1/analytics/credentials", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert "top_usernames" in body
        assert "top_passwords" in body
        assert "top_commands"  in body

    def test_geo_distribution(self, client, auth_headers):
        r = client.get("/api/v1/analytics/geo", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_service_trend(self, client, auth_headers):
        r = client.get("/api/v1/analytics/service-trend?days=7", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        if data:
            assert "day" in data[0] and "service" in data[0] and "count" in data[0]
