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


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to ensure current user has admin role."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user
