"""POST /api/v1/auth/login  (rate-limited: 10/min per IP)"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.rate_limit import limiter
from app.core.security import (
    add_token_to_blacklist,
    authenticate_user,
    create_access_token,
    create_refresh_token,
    extract_token_info,
    get_current_user,
    oauth2_scheme,
    verify_refresh_token,
)
from app.db.session import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.auth import Token, UserRead

router = APIRouter(prefix="/auth", tags=["Authentication"])


class RefreshRequest(BaseModel):
    """Body for the /refresh endpoint."""
    refresh_token: str


@router.post("/login", response_model=Token)
@limiter.limit("10/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Authenticate and return JWT access + refresh tokens. Rate-limited to 10/min per IP."""
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        settings=settings,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh = create_refresh_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        settings=settings,
    )

    # Log successful login to audit trail
    from app.api.deps import get_audit_repo
    client_ip = request.client.host if request.client else "0.0.0.0"
    get_audit_repo(db).log(
        username=user.username,
        action="LOGIN",
        client_ip=client_ip,
        target=user.username,
        description=f"User {user.username} authenticated successfully with role {user.role}.",
    )

    return Token(
        access_token=access,
        refresh_token=refresh,
        token_type="bearer",
        username=user.username,
        role=user.role,
    )


@router.post("/refresh", response_model=Token)
def refresh_token(
    body: RefreshRequest,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Exchange a valid refresh token for a new access + refresh token pair (token rotation)."""
    payload = verify_refresh_token(body.refresh_token, settings, db)

    username = payload.get("sub")
    user_id = payload.get("uid")
    role = payload.get("role", "analyst")

    # Blacklist the old refresh token (one-time use)
    old_jti = payload.get("jti")
    if old_jti:
        exp_ts = payload.get("exp", 0)
        add_token_to_blacklist(
            old_jti, username,
            datetime.fromtimestamp(exp_ts, tz=timezone.utc),
            db,
        )

    # Issue new pair
    new_access = create_access_token(
        user_id=user_id, username=username, role=role, settings=settings,
    )
    new_refresh = create_refresh_token(
        user_id=user_id, username=username, role=role, settings=settings,
    )

    return Token(
        access_token=new_access,
        refresh_token=new_refresh,
        token_type="bearer",
        username=username,
        role=role,
    )


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user's info."""
    return current_user


@router.post("/logout")
async def logout(
    request: Request,
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

        # Log successful logout to audit trail
        from app.api.deps import get_audit_repo
        client_ip = request.client.host if request.client else "0.0.0.0"
        get_audit_repo(db).log(
            username=current_user.username,
            action="LOGOUT",
            client_ip=client_ip,
            target=current_user.username,
            description=f"User {current_user.username} logged out successfully.",
        )
    return {"detail": "Successfully logged out."}
