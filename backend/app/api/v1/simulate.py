"""POST /api/v1/simulate – generate demo attack events (dev/demo only)."""
from fastapi import APIRouter, Depends, Query, Request

from app.api.deps import get_event_service
from app.api.v1.events import _get_real_ip
from app.core.security import get_current_user
from app.schemas.auth import UserInDB
from app.services.event_service import EventService
from app.services.geo_service import resolve_ip

router = APIRouter(prefix="/simulate", tags=["Simulation"])


@router.post("/", summary="Simulate attack events (demo)")
def simulate_attacks(
    request: Request,
    count: int = Query(default=30, ge=1, le=200, description="Number of events to generate"),
    current_user: UserInDB = Depends(get_current_user),
    svc: EventService = Depends(get_event_service),
):
    """
    Generate synthetic attack events from the caller's real IP.
    Useful for dashboard demos. Respects all normal ingest logic.
    """
    source_ip = resolve_ip(_get_real_ip(request))
    result = svc.simulate(source_ip=source_ip, count=count)
    result["triggered_by"] = current_user.username
    return result
