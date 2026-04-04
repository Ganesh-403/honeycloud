"""Analytics response Pydantic schemas."""
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class TimelineBucket(BaseModel):
    bucket: str
    total: int
    critical: int = 0
    high: int = 0
    severe: int = 0
    unique_ips: int = 0


class GeoEntry(BaseModel):
    country: str
    country_code: str
    flag: str
    event_count: int
    unique_ips: int


class HeatmapCell(BaseModel):
    hour: int        # 0–23
    day: int         # 0=Sun … 6=Sat
    count: int


class CredentialEntry(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    command:  Optional[str] = None
    attempts: int = 0
    uses:     int = 0
    unique_sources: int = 0
    service: Optional[str] = None


class ServiceTrend(BaseModel):
    day: str
    service: str
    count: int


class AnalyticsSummary(BaseModel):
    total_events:     int
    unique_attackers: int
    critical_total:   int
    malicious_total:  int
    latest_event:     Optional[str]
    avg_threat_score: float
