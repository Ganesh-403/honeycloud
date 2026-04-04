"""GET /api/v1/stats"""
from fastapi import APIRouter, Depends

from app.api.deps import get_event_service
from app.core.security import get_current_user
from app.schemas.auth import UserInDB
from app.schemas.stats import StatsResponse
from app.services.event_service import EventService

router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get("/", response_model=StatsResponse, summary="Dashboard statistics")
def get_stats(
    current_user: UserInDB = Depends(get_current_user),
    svc: EventService = Depends(get_event_service),
):
    """Aggregate counts by service, severity, and AI label."""
    return svc.get_stats()
