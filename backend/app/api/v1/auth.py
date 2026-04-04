"""POST /api/v1/auth/login  (rate-limited: 10/min per IP)"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.rate_limit import limiter
from app.core.security import (
    add_token_to_blacklist,
    authenticate_user,
    create_access_token,
    extract_token_info,
    get_current_user,
    oauth2_scheme,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import Token, UserRead

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=Token)
@limiter.limit("10/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Authenticate and return a JWT bearer token. Rate-limited to 10/min per IP."""
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        settings=settings,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return Token(access_token=token, token_type="bearer",
                 username=user.username, role=user.role)


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user's info."""
    return current_user


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    token: str = Depends(oauth2_scheme),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Revoke the current JWT token by adding it to the blacklist.
    After logout, the token cannot be used for authentication.
    """
    token_info = extract_token_info(token, settings)
    if token_info["jti"]:
        exp_datetime = datetime.fromtimestamp(token_info["exp"], tz=timezone.utc)
        add_token_to_blacklist(
            token_info["jti"],
            current_user.username,
            exp_datetime,
            db,
        )
    return {"detail": "Successfully logged out."}
