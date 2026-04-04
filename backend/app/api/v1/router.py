"""Aggregates all v1 sub-routers."""
from fastapi import APIRouter
from app.api.v1 import analytics, auth, events, ml, profiles, reports, simulate, stats

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(events.router)
api_router.include_router(stats.router)
api_router.include_router(analytics.router)
api_router.include_router(profiles.router)
api_router.include_router(reports.router)
api_router.include_router(simulate.router)
api_router.include_router(ml.router)
