"""
Attacker Profile routes.

Endpoints:
  GET  /api/v1/profiles/               – list profiles (filterable)
  GET  /api/v1/profiles/summary        – risk-tier breakdown counts
  GET  /api/v1/profiles/{ip}           – full profile for a single IP
  POST /api/v1/profiles/{ip}/block     – admin: block an IP
  POST /api/v1/profiles/{ip}/unblock   – admin: remove block
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_profile_repo
from app.core.security import get_current_user, require_admin
from app.repositories.profile_repository import ProfileRepository
from app.schemas.auth import UserInDB
from app.schemas.profile import BlockRequest, ProfileResponse, ProfileSummary

router = APIRouter(prefix="/profiles", tags=["Attacker Profiles"])


@router.get("/", response_model=list[ProfileSummary], summary="List attacker profiles")
def list_profiles(
    limit:        int  = Query(default=50, ge=1,  le=500),
    risk_tier:    str  = Query(default="",        description="Filter by risk tier"),
    blocked_only: bool = Query(default=False,      description="Only show blocked IPs"),
    current_user: UserInDB = Depends(get_current_user),
    repo: ProfileRepository = Depends(get_profile_repo),
):
    """
    Return attacker profiles sorted by total event count (highest first).
    Each profile aggregates all activity seen from that IP across all honeypots.
    """
    return repo.list_all(
        limit=limit,
        risk_tier=risk_tier or None,
        blocked_only=blocked_only,
    )


@router.get("/summary", summary="Risk tier breakdown")
def profile_summary(
    current_user: UserInDB = Depends(get_current_user),
    repo: ProfileRepository = Depends(get_profile_repo),
):
    """
    Counts of IPs per risk tier. Useful for the dashboard threat overview widget.
    Also returns total unique attacking IPs seen.
    """
    return {
        "by_risk_tier": repo.count_by_risk_tier(),
        "total_unique_ips": repo.total_unique_ips(),
        "top_attackers": [
            {
                "ip": p.ip_address,
                "events": p.total_events,
                "tier": p.risk_tier,
                "country": p.country,
                "brute_force": p.brute_force_detected,
            }
            for p in repo.top_by_events(limit=5)
        ],
    }


@router.get("/{ip_address}", response_model=ProfileResponse, summary="Profile for a single IP")
def get_profile(
    ip_address: str,
    current_user: UserInDB = Depends(get_current_user),
    repo: ProfileRepository = Depends(get_profile_repo),
):
    """
    Full attacker profile including: event history summary, geo info,
    detected attack patterns, top credentials used, and risk score breakdown.
    """
    profile = repo.get_by_ip(ip_address)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No profile found for IP: {ip_address}",
        )
    return profile


@router.post(
    "/{ip_address}/block",
    response_model=ProfileResponse,
    summary="Block an attacker IP (admin)",
)
def block_ip(
    ip_address: str,
    body: BlockRequest,
    current_user: UserInDB = Depends(require_admin),
    repo: ProfileRepository = Depends(get_profile_repo),
):
    """
    Admin-only. Marks an IP as blocked with a reason and timestamp.
    The is_blocked flag is checked by the ingest pipeline to auto-escalate severity.
    """
    profile = repo.get_by_ip(ip_address)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No profile found for IP: {ip_address}",
        )
    if profile.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{ip_address} is already blocked.",
        )

    profile.is_blocked   = True
    profile.block_reason = body.reason
    profile.blocked_at   = datetime.now(timezone.utc)
    profile.risk_tier    = "BLOCKED"
    return repo.save(profile)


@router.post(
    "/{ip_address}/unblock",
    response_model=ProfileResponse,
    summary="Remove block from an IP (admin)",
)
def unblock_ip(
    ip_address: str,
    current_user: UserInDB = Depends(require_admin),
    repo: ProfileRepository = Depends(get_profile_repo),
):
    """Admin-only. Removes the block flag and re-evaluates the risk tier."""
    profile = repo.get_by_ip(ip_address)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No profile found for IP: {ip_address}",
        )
    if not profile.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{ip_address} is not currently blocked.",
        )

    profile.is_blocked   = False
    profile.block_reason = None
    profile.blocked_at   = None
    # Recompute tier without BLOCKED override
    from app.services.profiler_service import _assign_tier, _compute_risk_score
    profile.risk_tier = _assign_tier(_compute_risk_score(profile), is_blocked=False)
    return repo.save(profile)
