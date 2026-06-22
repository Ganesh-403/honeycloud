"""
User management endpoints (admin-only).
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.api.deps import get_user_repo, get_audit_repo
from app.db.session import get_db
from app.core.security import require_admin
from app.schemas.auth import UserInDB, UserRead, UserCreate

router = APIRouter(prefix="/users", tags=["User Management"])


@router.get("/", response_model=list[UserRead], summary="List all active users")
def list_users(
    current_user: UserInDB = Depends(require_admin),
    user_repo = Depends(get_user_repo),
):
    """Admin-only. Lists all active, non-deleted users in the system."""
    return user_repo.list_all()


@router.post("/", response_model=UserRead, status_code=201, summary="Create a new user")
def create_user(
    body: UserCreate,
    request: Request,
    current_user: UserInDB = Depends(require_admin),
    user_repo = Depends(get_user_repo),
    db: Session = Depends(get_db),
):
    """Admin-only. Provision a new user account with specified username, password, and role."""
    if user_repo.exists(body.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{body.username}' is already taken.",
        )

    if body.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Role must be one of: admin, analyst",
        )

    user = user_repo.create(body.username, body.password, role=body.role)

    # Log action to audit trail
    client_ip = request.client.host if request.client else "0.0.0.0"
    get_audit_repo(db).log(
        username=current_user.username,
        action="CREATE_USER",
        client_ip=client_ip,
        target=body.username,
        description=f"Created new user '{body.username}' with role '{body.role}'.",
    )

    return user


@router.post("/{user_id}/deactivate", summary="Deactivate a user account")
def deactivate_user(
    user_id: int,
    request: Request,
    current_user: UserInDB = Depends(require_admin),
    user_repo = Depends(get_user_repo),
    db: Session = Depends(get_db),
):
    """Admin-only. Soft-delete/deactivate a user account, preventing subsequent login attempts."""
    user = user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or already inactive.",
        )

    if user.username == current_user.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account.",
        )

    user_repo.deactivate(user_id)

    # Log action to audit trail
    client_ip = request.client.host if request.client else "0.0.0.0"
    get_audit_repo(db).log(
        username=current_user.username,
        action="DEACTIVATE_USER",
        client_ip=client_ip,
        target=user.username,
        description=f"Deactivated user account '{user.username}' (ID {user_id}).",
    )

    return {"status": "success", "message": f"User '{user.username}' deactivated successfully."}
