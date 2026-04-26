"""Auth-related Pydantic schemas."""
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class TokenPayload(BaseModel):
    sub: str
    role: str = "analyst"


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserInDB(BaseModel):
    username: str
    hashed_password: str
    role: str


class UserRead(BaseModel):
    """User info for API responses (no password hash)."""
    id: int
    username: str
    role: str
    is_active: bool
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
