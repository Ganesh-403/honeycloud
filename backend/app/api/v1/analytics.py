"""
Analytics routes – all protected, analyst+ access.

Endpoints:
  GET /api/v1/analytics/summary          – overview card numbers
  GET /api/v1/analytics/timeline         – hourly or daily event counts
  GET /api/v1/analytics/geo              – events by country (map data)
  GET /api/v1/analytics/heatmap          – hour × day-of-week matrix
  GET /api/v1/analytics/credentials      – top usernames, passwords, commands
  GET /api/v1/analytics/service-trend    – per-service daily trend
"""
from fastapi import APIRouter, Depends, Query

from app.api.deps import get_analytics_repo
from app.core.security import get_current_user
from app.repositories.analytics_repository import AnalyticsRepository
from app.schemas.analytics import (
    AnalyticsSummary,
    CredentialEntry,
    GeoEntry,
    HeatmapCell,
    ServiceTrend,
    TimelineBucket,
)
from app.schemas.auth import UserInDB

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/summary", response_model=AnalyticsSummary, summary="Overview statistics")
def get_summary(
    current_user: UserInDB = Depends(get_current_user),
    repo: AnalyticsRepository = Depends(get_analytics_repo),
):
    """High-level numbers for the dashboard overview card."""
    return repo.summary()


@router.get("/timeline", response_model=list[TimelineBucket], summary="Attack timeline")
def get_timeline(
    mode: str = Query(default="hourly", pattern="^(hourly|daily)$",
                      description="hourly (last 24h) or daily (last 30 days)"),
    hours: int = Query(default=24, ge=1, le=168),
    days:  int = Query(default=30, ge=1, le=365),
    current_user: UserInDB = Depends(get_current_user),
    repo: AnalyticsRepository = Depends(get_analytics_repo),
):
    """
    Time-series data for line charts.
    - mode=hourly: one bucket per hour for the last `hours` hours
    - mode=daily : one bucket per day  for the last `days` days
    """
    if mode == "hourly":
        return repo.hourly_timeline(hours=hours)
    return repo.daily_timeline(days=days)


@router.get("/geo", response_model=list[GeoEntry], summary="Geographic distribution")
def get_geo(
    current_user: UserInDB = Depends(get_current_user),
    repo: AnalyticsRepository = Depends(get_analytics_repo),
):
    """
    Events aggregated by country – ready for a world-map choropleth chart.
    Returns top 50 countries sorted by event count.
    """
    return repo.geo_distribution()


@router.get("/heatmap", response_model=list[HeatmapCell], summary="Attack timing heatmap")
def get_heatmap(
    current_user: UserInDB = Depends(get_current_user),
    repo: AnalyticsRepository = Depends(get_analytics_repo),
):
    """
    24 × 7 matrix of event counts (hour-of-day × day-of-week).
    Returns a flat list; the client maps (hour, day) → count.

    Day encoding: 0=Sunday … 6=Saturday
    """
    return repo.attack_heatmap()


@router.get("/credentials", summary="Credential analysis")
def get_credentials(
    limit: int = Query(default=15, ge=5, le=50),
    current_user: UserInDB = Depends(get_current_user),
    repo: AnalyticsRepository = Depends(get_analytics_repo),
):
    """
    Most-used usernames, passwords, and commands across all captured attacks.
    Useful for identifying default-credential and brute-force patterns.
    """
    return {
        "top_usernames": repo.top_usernames(limit=limit),
        "top_passwords": repo.top_passwords(limit=limit),
        "top_commands":  repo.top_commands(limit=limit),
    }


@router.get("/service-trend", response_model=list[ServiceTrend], summary="Service trend")
def get_service_trend(
    days: int = Query(default=7, ge=1, le=90),
    current_user: UserInDB = Depends(get_current_user),
    repo: AnalyticsRepository = Depends(get_analytics_repo),
):
    """
    Daily event counts split by honeypot service (SSH / FTP / HTTP).
    Feed into a stacked bar or multi-line chart.
    """
    return repo.service_trend(days=days)
