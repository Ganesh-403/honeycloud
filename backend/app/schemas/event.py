"""
Attack event Pydantic schemas.
Handles ingest validation and API response shapes.
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator, IPvAnyAddress


# ---------------------------------------------------------------------------
# Sub-schemas
# ---------------------------------------------------------------------------

class LocationInfo(BaseModel):
    city: str = "Unknown"
    country: str = "Unknown"
    country_code: str = "XX"
    flag: str = "🌍"
    region: str = ""
    isp: str = "Unknown ISP"
    abuse_score: int = 0
    total_reports: int = 0
    is_whitelisted: bool = False
    usage_type: str = "Unknown"


# ---------------------------------------------------------------------------
# Ingest (public POST /api/v1/ingest)
# ---------------------------------------------------------------------------

VALID_SERVICES = {"SSH", "FTP", "HTTP", "TELNET", "EXTERNAL"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_AI_LABELS = {"benign", "anomaly", "malicious", "unknown"}
VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "UNKNOWN"}


class EventIngest(BaseModel):
    """Payload sent by honeypot agents to /api/v1/ingest."""
    source_ip: Optional[str] = None
    source_port: int = Field(default=0, ge=0, le=65535)
    service: str = "EXTERNAL"
    username: Optional[str] = Field(default=None, max_length=255)
    password: Optional[str] = Field(default=None, max_length=255)
    command: Optional[str] = Field(default=None, max_length=1000)
    payload: Optional[str] = Field(default=None, max_length=4096)
    method: str = "UNKNOWN"
    endpoint: Optional[str] = Field(default=None, max_length=500)
    severity: str = "MEDIUM"
    ai_label: str = "anomaly"
    threat_score: float = Field(default=0.5, ge=0.0, le=1.0)
    timestamp: Optional[datetime] = None
    metadata: dict = Field(default_factory=dict)

    @field_validator("service")
    @classmethod
    def validate_service(cls, v: str) -> str:
        return v.upper() if v.upper() in VALID_SERVICES else "EXTERNAL"

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        v_upper = v.upper()
        return v_upper if v_upper in VALID_SEVERITIES else "MEDIUM"

    @field_validator("ai_label")
    @classmethod
    def validate_ai_label(cls, v: str) -> str:
        v_lower = v.lower()
        return v_lower if v_lower in VALID_AI_LABELS else "unknown"

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        v_upper = v.upper()
        return v_upper if v_upper in VALID_METHODS else "UNKNOWN"


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------

class EventResponse(BaseModel):
    id: int
    timestamp: datetime
    service: str
    source_ip: str
    source_port: int
    username: Optional[str]
    password: Optional[str]
    command: Optional[str]
    payload: Optional[str]
    method: str
    endpoint: Optional[str]
    severity: str
    ai_label: str
    threat_score: float
    location: LocationInfo
    metadata: dict

    class Config:
        from_attributes = True


class IngestResponse(BaseModel):
    status: str = "received"
    id: int


# ---------------------------------------------------------------------------
# Query filters
# ---------------------------------------------------------------------------

class EventFilters(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)
    service: Optional[str] = None
    severity: Optional[str] = None
