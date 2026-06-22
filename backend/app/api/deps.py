"""
Shared FastAPI dependency providers.
Import from here – never instantiate services inside route functions.
"""
from functools import lru_cache

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.ml.detector import MLThreatDetector
from app.ml.rf_detector import RFDetector
from app.repositories.analytics_repository import AnalyticsRepository
from app.repositories.alert_repository import AlertRepository
from app.repositories.event_repository import EventRepository
from app.repositories.mitre_repository import MitreRepository
from app.repositories.profile_repository import ProfileRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.token_blacklist_repository import TokenBlacklistRepository
from app.repositories.user_repository import UserRepository
from app.repositories.audit_repository import AuditRepository
from app.services.alert_service import AlertService
from app.services.email_service import EmailAlertService
from app.services.event_service import EventService
from app.services.mitre_service import MitreService
from app.services.report_service import ReportService


# ── Process-level singletons ──────────────────────────────────────────────────

@lru_cache
def get_alert_service() -> AlertService:
    return AlertService()


@lru_cache
def get_email_service() -> EmailAlertService:
    return EmailAlertService()


@lru_cache
def get_ml_detector() -> MLThreatDetector:
    return MLThreatDetector()


@lru_cache
def get_rf_detector() -> RFDetector:
    return RFDetector()


@lru_cache
def get_mitre_service() -> MitreService:
    return MitreService()


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


def get_audit_repo(db: Session = Depends(get_db)) -> AuditRepository:
    return AuditRepository(db)


def get_mitre_repo(db: Session = Depends(get_db)) -> MitreRepository:
    return MitreRepository(db)


def get_alert_repo(db: Session = Depends(get_db)) -> AlertRepository:
    return AlertRepository(db)


def get_report_repo(db: Session = Depends(get_db)) -> ReportRepository:
    return ReportRepository(db)


def get_role_repo(db: Session = Depends(get_db)) -> RoleRepository:
    return RoleRepository(db)


def get_event_service(
    repo: EventRepository = Depends(get_event_repo),
    alert_svc: AlertService = Depends(get_alert_service),
    email_svc: EmailAlertService = Depends(get_email_service),
    detector: MLThreatDetector = Depends(get_ml_detector),
) -> EventService:
    return EventService(repo, alert_svc, email_svc, detector)
