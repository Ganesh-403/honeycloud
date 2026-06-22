"""
MITRE ATT&CK analytics routes.

  GET  /api/v1/mitre/techniques       – all known MITRE technique definitions
  GET  /api/v1/mitre/stats            – technique and tactic breakdowns
  GET  /api/v1/mitre/event/{event_id} – MITRE mappings for a specific event
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_mitre_repo, get_mitre_service
from app.core.security import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.repositories.mitre_repository import MitreRepository
from app.services.mitre_service import MitreService

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


@router.get("/techniques", summary="List all known MITRE ATT&CK techniques")
def list_techniques(
    current_user: User = Depends(get_current_user),
    mitre_svc: MitreService = Depends(get_mitre_service),
):
    """Return all MITRE ATT&CK techniques the platform can detect."""
    return mitre_svc.get_all_techniques()


@router.get("/stats", summary="MITRE ATT&CK analytics breakdown")
def mitre_stats(
    current_user: User = Depends(get_current_user),
    mitre_repo: MitreRepository = Depends(get_mitre_repo),
):
    """Return aggregated counts of events per technique and per tactic."""
    return {
        "by_technique": mitre_repo.count_by_technique(),
        "by_tactic":    mitre_repo.count_by_tactic(),
    }


@router.get("/event/{event_id}", summary="MITRE mappings for a specific event")
def event_mappings(
    event_id: int,
    current_user: User = Depends(get_current_user),
    mitre_repo: MitreRepository = Depends(get_mitre_repo),
):
    """Return all MITRE ATT&CK technique mappings for a specific event."""
    mappings = mitre_repo.get_by_event(event_id)
    return [
        {
            "technique_id":   m.technique_id,
            "technique_name": m.technique_name,
            "tactic":         m.tactic,
            "confidence":     m.confidence,
            "mapped_at":      str(m.mapped_at),
        }
        for m in mappings
    ]
