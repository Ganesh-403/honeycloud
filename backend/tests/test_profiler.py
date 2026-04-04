"""Tests for ProfilerService pattern detection logic."""
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


def _make_event(ip="1.1.1.1", service="SSH", severity="HIGH",
                username="root", password="pass"):
    """Build a minimal AttackEvent-like mock."""
    e = MagicMock()
    e.source_ip   = ip
    e.service     = service
    e.severity    = severity
    e.username    = username
    e.password    = password
    e.command     = "ls"
    e.geolocation = {"city": "X", "country": "Y", "country_code": "XY", "isp": "ISP"}
    e.timestamp   = datetime.now(timezone.utc)
    return e


class TestProfilerService:
    def test_process_creates_new_profile(self, db_session):
        from app.services.profiler_service import ProfilerService
        from app.repositories.profile_repository import ProfileRepository

        svc = ProfilerService(db_session)
        event = _make_event()
        profile = svc.process_event(event)

        assert profile.ip_address == "1.1.1.1"
        assert profile.total_events == 1
        assert "SSH" in profile.services_targeted

    def test_risk_score_increases_with_severity(self, db_session):
        from app.services.profiler_service import ProfilerService

        svc = ProfilerService(db_session)
        ip = "2.2.2.2"
        for _ in range(3):
            svc.process_event(_make_event(ip=ip, severity="CRITICAL"))
        profile = svc.process_event(_make_event(ip=ip, severity="CRITICAL"))
        assert profile.risk_score > 0
        assert profile.critical_count >= 4

    def test_geo_filled_from_first_event(self, db_session):
        from app.services.profiler_service import ProfilerService

        svc = ProfilerService(db_session)
        event = _make_event(ip="3.3.3.3")
        profile = svc.process_event(event)
        assert profile.country == "Y"
        assert profile.city == "X"

    def test_credential_tracking(self, db_session):
        from app.services.profiler_service import ProfilerService

        svc = ProfilerService(db_session)
        ip = "4.4.4.4"
        svc.process_event(_make_event(ip=ip, username="admin", password="p1"))
        svc.process_event(_make_event(ip=ip, username="admin", password="p2"))
        profile = svc.process_event(_make_event(ip=ip, username="root", password="p1"))
        assert "admin" in profile.username_counts
        assert profile.username_counts["admin"] == 2

    def test_services_tracked(self, db_session):
        from app.services.profiler_service import ProfilerService

        svc = ProfilerService(db_session)
        ip = "5.5.5.5"
        svc.process_event(_make_event(ip=ip, service="SSH"))
        profile = svc.process_event(_make_event(ip=ip, service="HTTP"))
        assert "SSH" in profile.services_targeted
        assert "HTTP" in profile.services_targeted

    def test_risk_tier_critical(self, db_session):
        from app.services.profiler_service import ProfilerService

        svc = ProfilerService(db_session)
        ip = "6.6.6.6"
        for _ in range(15):
            svc.process_event(_make_event(ip=ip, severity="CRITICAL"))
        profile = svc.process_event(_make_event(ip=ip, severity="CRITICAL"))
        assert profile.risk_tier in ("CRITICAL", "HIGH")
