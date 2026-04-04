"""Tests for authentication endpoints."""
import pytest
from tests.conftest import SAMPLE_INGEST


class TestAuth:
    def test_login_success(self, client):
        r = client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin123"})
        assert r.status_code == 200
        body = r.json()
        assert "access_token" in body
        assert body["role"] == "admin"
        assert body["token_type"] == "bearer"

    def test_login_wrong_password(self, client):
        r = client.post("/api/v1/auth/login", data={"username": "admin", "password": "wrongpass"})
        assert r.status_code == 401

    def test_login_unknown_user(self, client):
        r = client.post("/api/v1/auth/login", data={"username": "nobody", "password": "x"})
        assert r.status_code == 401

    def test_me_authenticated(self, client, auth_headers):
        r = client.get("/api/v1/auth/me", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["username"] == "admin"

    def test_me_unauthenticated(self, client):
        r = client.get("/api/v1/auth/me")
        assert r.status_code == 401

    def test_analyst_role(self, client, analyst_headers):
        r = client.get("/api/v1/auth/me", headers=analyst_headers)
        assert r.status_code == 200
        assert r.json()["role"] == "analyst"
