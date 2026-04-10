"""Tests for attacker profile API endpoints."""
import pytest
from tests.conftest import SAMPLE_INGEST


@pytest.fixture
def seeded_ip(client):
    """Ingest 3 events from a fixed IP so a profile exists."""
    ip = "11.20.30.40"
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        client.post("/api/v1/events/ingest", json={**SAMPLE_INGEST, "source_ip": ip, "severity": sev})
    return ip


class TestProfileEndpoints:
    def test_list_profiles_requires_auth(self, client):
        r = client.get("/api/v1/profiles/")
        assert r.status_code == 401

    def test_list_profiles_returns_list(self, client, auth_headers, seeded_ip):
        r = client.get("/api/v1/profiles/", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_profiles_filter_by_tier(self, client, auth_headers):
        r = client.get("/api/v1/profiles/?risk_tier=UNKNOWN", headers=auth_headers)
        assert r.status_code == 200

    def test_profile_summary_structure(self, client, auth_headers, seeded_ip):
        r = client.get("/api/v1/profiles/summary", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert "by_risk_tier" in body
        assert "total_unique_ips" in body
        assert "top_attackers" in body

    def test_get_profile_by_ip(self, client, auth_headers, seeded_ip):
        r = client.get(f"/api/v1/profiles/{seeded_ip}", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["ip_address"] == seeded_ip
        assert body["total_events"] >= 3
        assert "risk_score" in body
        assert "risk_tier" in body

    def test_get_profile_not_found(self, client, auth_headers):
        r = client.get("/api/v1/profiles/99.99.99.99", headers=auth_headers)
        assert r.status_code == 404

    def test_block_requires_admin(self, client, analyst_headers, seeded_ip):
        r = client.post(
            f"/api/v1/profiles/{seeded_ip}/block",
            json={"reason": "test"},
            headers=analyst_headers,
        )
        assert r.status_code == 403

    def test_block_and_unblock(self, client, auth_headers, seeded_ip):
        # Block
        r = client.post(
            f"/api/v1/profiles/{seeded_ip}/block",
            json={"reason": "suspicious activity"},
            headers=auth_headers,
        )
        assert r.status_code == 200
        assert r.json()["is_blocked"] is True
        assert r.json()["risk_tier"] == "BLOCKED"

        # Double-block → 409
        r2 = client.post(
            f"/api/v1/profiles/{seeded_ip}/block",
            json={"reason": "again"},
            headers=auth_headers,
        )
        assert r2.status_code == 409

        # Unblock
        r3 = client.post(f"/api/v1/profiles/{seeded_ip}/unblock", headers=auth_headers)
        assert r3.status_code == 200
        assert r3.json()["is_blocked"] is False
