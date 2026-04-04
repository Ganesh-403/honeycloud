"""Stats and report Pydantic schemas."""
from datetime import datetime
from typing import Dict

from pydantic import BaseModel


class StatsResponse(BaseModel):
    total_events: int
    events_by_service: Dict[str, int]
    events_by_severity: Dict[str, int]
    ai_labels: Dict[str, int]
    last_updated: datetime


class ReportResponse(BaseModel):
    status: str
    message: str
    filepath: str
    events_count: int
    download_url: str
