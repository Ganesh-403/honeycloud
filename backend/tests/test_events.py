"""Tests for event ingest and listing endpoints."""
import pytest
from tests.conftest import SAMPLE_INGEST


class TestIngest:
    def test_ingest_returns_201(self, client):
        r = client.post("/api/v1/events/ingest", json=SAMPLE_INGEST)
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "received"
        assert isinstance(body["id"], int)

    def test_ingest_no_auth_required(self, client):
        """Ingest is a public endpoint – no JWT needed."""
        r = client.post("/api/v1/events/ingest", json={
            "service": "HTTP", "source_ip": "5.6.7.8", "severity": "LOW"
        })
        assert r.status_code == 201

    def test_ingest_invalid_service_coerced(self, client):
        """Unknown service is coerced to EXTERNAL, not rejected."""
        r = client.post("/api/v1/events/ingest", json={
            "service": "TELNET", "source_ip": "9.9.9.9", "severity": "LOW"
        })
        assert r.status_code == 201

    def test_ingest_invalid_severity_coerced(self, client):
        r = client.post("/api/v1/events/ingest", json={
            "service": "SSH", "source_ip": "9.9.9.9", "severity": "EXTREME"
        })
        assert r.status_code == 201  # coerced to MEDIUM

    def test_ingest_threat_score_clamped(self, client):
        """threat_score outside [0,1] should be rejected by Pydantic."""
        r = client.post("/api/v1/events/ingest", json={
            **SAMPLE_INGEST, "threat_score": 99.0
        })
        assert r.status_code == 422

    def test_list_events_requires_auth(self, client):
        r = client.get("/api/v1/events/")
        assert r.status_code == 401

    def test_list_events_returns_list(self, client, auth_headers):
        # Ensure at least one event exists
        client.post("/api/v1/events/ingest", json=SAMPLE_INGEST)
        r = client.get("/api/v1/events/?limit=10", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_events_filter_by_service(self, client, auth_headers):
        client.post("/api/v1/events/ingest", json={**SAMPLE_INGEST, "service": "FTP"})
        r = client.get("/api/v1/events/?service=FTP&limit=50", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert all(e["service"] == "FTP" for e in data)

    def test_list_events_filter_by_severity(self, client, auth_headers):
        client.post("/api/v1/events/ingest", json={**SAMPLE_INGEST, "severity": "LOW"})
        r = client.get("/api/v1/events/?severity=LOW&limit=50", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert all(e["severity"] == "LOW" for e in data)

    def test_list_events_limit_respected(self, client, auth_headers):
        for _ in range(5):
            client.post("/api/v1/events/ingest", json=SAMPLE_INGEST)
        r = client.get("/api/v1/events/?limit=2", headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json()) <= 2

    def test_event_response_schema(self, client, auth_headers):
        """Response must include all required fields."""
        client.post("/api/v1/events/ingest", json=SAMPLE_INGEST)
        r = client.get("/api/v1/events/?limit=1", headers=auth_headers)
        event = r.json()[0]
        required = {"id", "timestamp", "service", "source_ip", "severity", "ai_label", "threat_score", "location"}
        assert required.issubset(event.keys())
