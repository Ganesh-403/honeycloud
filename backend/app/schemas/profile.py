"""AttackerProfile Pydantic schemas."""
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class ProfileResponse(BaseModel):
    id: int
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    total_events: int
    critical_count: int
    high_count: int
    country: Optional[str]
    country_code: Optional[str]
    city: Optional[str]
    isp: Optional[str]
    services_targeted: list[str]
    top_username: Optional[str]
    top_password: Optional[str]
    risk_score: float
    risk_tier: str
    brute_force_detected: bool
    credential_stuffing_detected: bool
    scanner_detected: bool
    is_blocked: bool
    block_reason: Optional[str]
    blocked_at: Optional[datetime]

    class Config:
        from_attributes = True


class BlockRequest(BaseModel):
    reason: str = "Manual block by administrator"


class ProfileSummary(BaseModel):
    """Lightweight profile for list views."""
    ip_address: str
    total_events: int
    risk_tier: str
    risk_score: float
    country: Optional[str]
    is_blocked: bool
    brute_force_detected: bool
    scanner_detected: bool
    last_seen: datetime

    class Config:
        from_attributes = True
