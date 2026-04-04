"""
Shared FastAPI dependency providers.
Import from here – never instantiate services inside route functions.
"""
from functools import lru_cache

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.ml.detector import MLThreatDetector
from app.repositories.analytics_repository import AnalyticsRepository
from app.repositories.event_repository import EventRepository
from app.repositories.profile_repository import ProfileRepository
from app.repositories.token_blacklist_repository import TokenBlacklistRepository
from app.repositories.user_repository import UserRepository
from app.services.alert_service import AlertService
from app.services.event_service import EventService
from app.services.report_service import ReportService


# ── Process-level singletons ──────────────────────────────────────────────────

@lru_cache
def get_alert_service() -> AlertService:
    return AlertService()


@lru_cache
def get_ml_detector() -> MLThreatDetector:
    return MLThreatDetector()


@lru_cache
def get_report_service() -> ReportService:
    return ReportService()


# ── Per-request dependencies ──────────────────────────────────────────────────

def get_event_repo(db: Session = Depends(get_db)) -> EventRepository:
    return EventRepository(db)


def get_profile_repo(db: Session = Depends(get_db)) -> ProfileRepository:
    return ProfileRepository(db)


def get_analytics_repo(db: Session = Depends(get_db)) -> AnalyticsRepository:
    return AnalyticsRepository(db)


def get_user_repo(db: Session = Depends(get_db)) -> UserRepository:
    return UserRepository(db)


def get_token_blacklist_repo(db: Session = Depends(get_db)) -> TokenBlacklistRepository:
    return TokenBlacklistRepository(db)


def get_event_service(
    repo: EventRepository = Depends(get_event_repo),
    alert_svc: AlertService = Depends(get_alert_service),
    detector: MLThreatDetector = Depends(get_ml_detector),
) -> EventService:
    return EventService(repo, alert_svc, detector)
