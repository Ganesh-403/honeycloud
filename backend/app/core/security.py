"""
Security utilities: JWT token creation/verification, password hashing.
Database-backed user authentication with token revocation support.
All secrets are sourced from Settings – never hardcoded here.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.session import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.repositories.token_blacklist_repository import TokenBlacklistRepository
from app.schemas.auth import TokenPayload, UserInDB

logger = get_logger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# Role hierarchy: higher weight = more privileges
ROLE_WEIGHT = {"owner": 30, "admin": 20, "analyst": 10}

REFRESH_TOKEN_EXPIRE_DAYS = 7

# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    """Hash a plain password using bcrypt."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain password against a bcrypt hash."""
    return pwd_context.verify(plain, hashed)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(
    user_id: int,
    username: str,
    role: str,
    settings: Settings,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token with unique jti for revocation tracking."""
    payload = {
        "sub": username,
        "uid": user_id,
        "role": role,
        "type": "access",
        "jti": str(uuid.uuid4()),  # JWT ID for revocation
    }
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload["exp"] = expire
    payload["iat"] = now

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token


def create_refresh_token(
    user_id: int,
    username: str,
    role: str,
    settings: Settings,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a long-lived JWT refresh token."""
    payload = {
        "sub": username,
        "uid": user_id,
        "role": role,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
    }
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    payload["exp"] = expire
    payload["iat"] = now

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token


def verify_refresh_token(
    token: str,
    settings: Settings,
    db: Session,
) -> dict:
    """
    Verify a refresh token and return payload.
    Raises HTTPException on invalid/expired/blacklisted tokens.
    """
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": True},
        )
        if payload.get("type") != "refresh":
            raise credentials_exc

        token_jti = payload.get("jti")
        if token_jti and is_token_blacklisted(token_jti, db):
            raise credentials_exc

        return payload
    except JWTError:
        raise credentials_exc


# ---------------------------------------------------------------------------
# User authentication (DB-backed)
# ---------------------------------------------------------------------------

def authenticate_user(
    username: str,
    password: str,
    db: Session,
) -> Optional[User]:
    """
    Authenticate a user by username and password.
    Returns the User object if credentials are valid, None otherwise.
    """
    repo = UserRepository(db)
    user = repo.get_by_username(username)
    
    if not user:
        logger.warning("Login attempt for non-existent user: %s", username)
        return None
    
    if not verify_password(password, user.hashed_password):
        logger.warning("Failed login attempt (wrong password) for user: %s", username)
        return None
    
    logger.info("Successful login: %s", username)
    # Update last_login timestamp
    repo.update_last_login(user.id)
    return user


# ---------------------------------------------------------------------------
# Token blacklist management
# ---------------------------------------------------------------------------

def is_token_blacklisted(token_jti: str, db: Session) -> bool:
    """Check if a token JWT ID has been blacklisted (revoked)."""
    repo = TokenBlacklistRepository(db)
    return repo.is_blacklisted(token_jti)


def add_token_to_blacklist(
    jti: str,
    username: str,
    expires_at: datetime,
    db: Session,
) -> None:
    """Add a token JWT ID to the blacklist (logout/revocation)."""
    repo = TokenBlacklistRepository(db)
    repo.add_to_blacklist(jti, username, expires_at)
    logger.info("Token blacklisted for user: %s", username)


def extract_token_info(token: str, settings: Settings) -> dict:
    """Extract jti, exp, and username from a JWT token without validation.
    Used for logout to extract token info before blacklisting.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": False},  # Allow expired tokens for logout
        )
        return {
            "jti": payload.get("jti"),
            "username": payload.get("sub"),
            "exp": payload.get("exp"),
        }
    except JWTError:
        return {"jti": None, "username": None, "exp": None}


# ---------------------------------------------------------------------------
# Role hierarchy helpers
# ---------------------------------------------------------------------------

def _get_role_weight(role: str) -> int:
    """Return the numeric weight for a role string."""
    return ROLE_WEIGHT.get(role.lower(), 0)


def _check_minimum_role(user: User, min_role: str) -> None:
    """Raise 403 if user's role weight is below the minimum required."""
    user_weight = _get_role_weight(user.role)
    required_weight = _get_role_weight(min_role)
    if user_weight < required_weight:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{min_role.capitalize()} access required. Your role: {user.role}.",
        )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> User:
    """
    Dependency to get the current authenticated user from JWT token.
    Validates token expiration, signature, and blacklist status.
    Returns the User object from database.
    """
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": True},
        )
        username: Optional[str] = payload.get("sub")
        user_id: Optional[int] = payload.get("uid")
        token_jti: Optional[str] = payload.get("jti")
        
        if username is None or user_id is None or token_jti is None:
            raise credentials_exc
        
        # Check if token is blacklisted
        if is_token_blacklisted(token_jti, db):
            logger.warning("Attempt to use blacklisted token for user: %s", username)
            raise credentials_exc
        
        token_data = TokenPayload(sub=username, role=payload.get("role", "analyst"))
    except JWTError as e:
        logger.debug("JWT validation error: %s", e)
        raise credentials_exc

    # Fetch user from database
    repo = UserRepository(db)
    user = repo.get_by_id(user_id)
    
    if user is None or user.username != username:
        logger.warning("User not found or username mismatch for token: %s", username)
        raise credentials_exc
    
    return user


async def require_owner(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to ensure current user has owner role (highest privilege)."""
    _check_minimum_role(current_user, "owner")
    return current_user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to ensure current user has admin role or higher (owner inherits admin)."""
    _check_minimum_role(current_user, "admin")
    return current_user


async def require_analyst(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to ensure current user has at least analyst role (any authenticated user)."""
    _check_minimum_role(current_user, "analyst")
    return current_user

