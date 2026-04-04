"""
ProfilerService – builds and maintains per-IP attacker profiles.

Responsibilities:
  1. Upsert an AttackerProfile record on every ingest event
  2. Run pattern detection (brute force, credential stuffing, scanner)
  3. Compute a risk score and assign a risk tier
  4. Flag the profile when patterns are detected

Pattern detection thresholds (configurable via Settings):
  - Brute force          : ≥ BRUTE_FORCE_THRESHOLD events in BRUTE_FORCE_WINDOW_SECS
  - Credential stuffing  : ≥ STUFFING_THRESHOLD unique passwords in STUFFING_WINDOW_SECS
  - Scanner              : ≥ SCANNER_THRESHOLD distinct services in SCANNER_WINDOW_SECS
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.attack_event import AttackEvent
from app.models.attacker_profile import AttackerProfile
from app.repositories.profile_repository import ProfileRepository

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)
settings = get_settings()

# ── Thresholds ────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD   = 10    # events from same IP
BRUTE_FORCE_WINDOW_SECS = 60
STUFFING_THRESHOLD      = 5     # unique passwords from same IP
STUFFING_WINDOW_SECS    = 300
SCANNER_THRESHOLD       = 3     # distinct services from same IP
SCANNER_WINDOW_SECS     = 300

# ── Risk tier boundaries (event count × severity weights) ─────────────────────
SEVERITY_WEIGHTS = {"CRITICAL": 4.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.25}
TIER_THRESHOLDS  = [
    (50.0,  "CRITICAL"),
    (20.0,  "HIGH"),
    (8.0,   "MEDIUM"),
    (2.0,   "LOW"),
    (0.0,   "UNKNOWN"),
]


def _compute_risk_score(profile: AttackerProfile) -> float:
    """Weighted score: severity counts × weights + pattern bonuses."""
    score = (
        profile.critical_count * SEVERITY_WEIGHTS["CRITICAL"]
        + profile.high_count   * SEVERITY_WEIGHTS["HIGH"]
    )
    if profile.brute_force_detected:
        score += 15.0
    if profile.credential_stuffing_detected:
        score += 10.0
    if profile.scanner_detected:
        score += 8.0
    return round(score, 2)


def _assign_tier(score: float, is_blocked: bool) -> str:
    if is_blocked:
        return "BLOCKED"
    for threshold, tier in TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "UNKNOWN"


class ProfilerService:
    """
    Called by EventService after each successful event ingest.
    Designed to run as a background task (owns its own DB session).
    """

    def __init__(self, db: Session):
        self._db = db
        self._repo = ProfileRepository(db)

    # ── Public ────────────────────────────────────────────────────────────────

    def process_event(self, event: AttackEvent) -> AttackerProfile:
        """
        Main entry point. Upsert the profile, detect patterns, recompute risk.
        Returns the updated profile.
        """
        profile, _ = self._repo.get_or_create(event.source_ip)

        self._update_counters(profile, event)
        self._update_geo(profile, event)
        self._update_credentials(profile, event)
        self._detect_patterns(profile)

        profile.risk_score = _compute_risk_score(profile)
        profile.risk_tier  = _assign_tier(profile.risk_score, profile.is_blocked)
        profile.last_seen  = datetime.now(timezone.utc)

        saved = self._repo.save(profile)
        logger.debug(
            "Profile updated | ip=%s tier=%s score=%.1f brute=%s scanner=%s",
            saved.ip_address, saved.risk_tier, saved.risk_score,
            saved.brute_force_detected, saved.scanner_detected,
        )
        return saved

    # ── Private helpers ───────────────────────────────────────────────────────

    def _update_counters(self, profile: AttackerProfile, event: AttackEvent) -> None:
        profile.total_events = (profile.total_events or 0) + 1
        if event.severity == "CRITICAL":
            profile.critical_count = (profile.critical_count or 0) + 1
        elif event.severity == "HIGH":
            profile.high_count = (profile.high_count or 0) + 1

        svcs = list(profile.services_targeted or [])
        if event.service and event.service not in svcs:
            svcs.append(event.service)
        profile.services_targeted = svcs

    def _update_geo(self, profile: AttackerProfile, event: AttackEvent) -> None:
        """Fill geo fields from event on first enriched event."""
        if profile.country:
            return
        geo = event.geolocation or {}
        profile.country      = geo.get("country")
        profile.country_code = geo.get("country_code")
        profile.city         = geo.get("city")
        profile.isp          = geo.get("isp")

    def _update_credentials(self, profile: AttackerProfile, event: AttackEvent) -> None:
        """Track username/password frequency for credential analysis."""
        ucounts = dict(profile.username_counts or {})
        pcounts = dict(profile.password_counts or {})

        if event.username:
            ucounts[event.username] = ucounts.get(event.username, 0) + 1
            profile.top_username = max(ucounts, key=ucounts.get)
        if event.password:
            pcounts[event.password] = pcounts.get(event.password, 0) + 1
            profile.top_password = max(pcounts, key=pcounts.get)

        profile.username_counts = ucounts
        profile.password_counts = pcounts

    def _detect_patterns(self, profile: AttackerProfile) -> None:
        """Run all pattern detectors; set flags on the profile."""
        ip = profile.ip_address

        if not profile.brute_force_detected:
            profile.brute_force_detected = self._check_brute_force(ip)

        if not profile.credential_stuffing_detected:
            profile.credential_stuffing_detected = self._check_credential_stuffing(ip)

        if not profile.scanner_detected:
            profile.scanner_detected = self._check_scanner(ip)

    def _check_brute_force(self, ip: str) -> bool:
        since = datetime.now(timezone.utc) - timedelta(seconds=BRUTE_FORCE_WINDOW_SECS)
        count = self._db.scalar(
            text("""
                SELECT COUNT(*) FROM attack_events
                WHERE source_ip = :ip AND timestamp >= :since
            """),
            {"ip": ip, "since": since.isoformat()},
        ) or 0
        if count >= BRUTE_FORCE_THRESHOLD:
            logger.warning("BRUTE FORCE detected from %s (%d events in %ds)", ip, count, BRUTE_FORCE_WINDOW_SECS)
            return True
        return False

    def _check_credential_stuffing(self, ip: str) -> bool:
        since = datetime.now(timezone.utc) - timedelta(seconds=STUFFING_WINDOW_SECS)
        row = self._db.execute(
            text("""
                SELECT COUNT(DISTINCT password) FROM attack_events
                WHERE source_ip = :ip
                  AND password IS NOT NULL
                  AND timestamp >= :since
            """),
            {"ip": ip, "since": since.isoformat()},
        ).scalar()
        count = row or 0
        if count >= STUFFING_THRESHOLD:
            logger.warning("CREDENTIAL STUFFING detected from %s (%d unique passwords)", ip, count)
            return True
        return False

    def _check_scanner(self, ip: str) -> bool:
        since = datetime.now(timezone.utc) - timedelta(seconds=SCANNER_WINDOW_SECS)
        row = self._db.execute(
            text("""
                SELECT COUNT(DISTINCT service) FROM attack_events
                WHERE source_ip = :ip AND timestamp >= :since
            """),
            {"ip": ip, "since": since.isoformat()},
        ).scalar()
        count = row or 0
        if count >= SCANNER_THRESHOLD:
            logger.warning("SCANNER detected from %s (%d services in %ds)", ip, count, SCANNER_WINDOW_SECS)
            return True
        return False
