"""Tests for security hardening: token rejection, RBAC, path traversal protection."""
import pytest


class TestSecurity:
    def test_invalid_token_rejected(self, client):
        r = client.get("/api/v1/events/", headers={"Authorization": "Bearer fake.token.here"})
        assert r.status_code == 401

    def test_expired_signature_rejected(self, client):
        # Tampered token
        r = client.get("/api/v1/events/", headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.wrongsig"})
        assert r.status_code == 401

    def test_analyst_cannot_generate_report(self, client, analyst_headers):
        r = client.post("/api/v1/reports/generate", headers=analyst_headers)
        assert r.status_code == 403

    def test_analyst_cannot_train_ml(self, client, analyst_headers):
        r = client.post("/api/v1/ml/train", headers=analyst_headers)
        assert r.status_code == 403

    def test_analyst_can_read_events(self, client, analyst_headers):
        r = client.get("/api/v1/events/?limit=5", headers=analyst_headers)
        assert r.status_code == 200

    def test_analyst_can_read_analytics(self, client, analyst_headers):
        r = client.get("/api/v1/analytics/summary", headers=analyst_headers)
        assert r.status_code == 200

    def test_path_traversal_on_download(self, client, auth_headers):
        r = client.get("/api/v1/reports/download?file=../../etc/passwd", headers=auth_headers)
        assert r.status_code in (400, 404)

    def test_path_traversal_with_null_byte(self, client, auth_headers):
        r = client.get("/api/v1/reports/download?file=report.csv%00../../etc/passwd", headers=auth_headers)
        assert r.status_code in (400, 404)

    def test_ingest_oversized_payload_rejected(self, client):
        r = client.post("/api/v1/events/ingest", json={
            "service": "SSH",
            "source_ip": "1.1.1.1",
            "command": "A" * 2000,  # exceeds max_length=1000
        })
        assert r.status_code == 422

    def test_health_unauthenticated(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

    def test_root_unauthenticated(self, client):
        r = client.get("/")
        assert r.status_code == 200
