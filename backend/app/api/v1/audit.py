"""
Audit Log query endpoints (admin-only).
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from app.api.deps import get_audit_repo
from app.core.security import require_admin
from app.schemas.auth import UserInDB
from app.schemas.audit import AuditLogRead

router = APIRouter(prefix="/audit", tags=["Audit Logs"])


@router.get("/", response_model=list[AuditLogRead], summary="List system audit logs")
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    username: Optional[str] = Query(default=None, description="Filter by actor username"),
    action: Optional[str] = Query(default=None, description="Filter by action type (e.g. LOGIN, BLOCK_IP)"),
    current_user: UserInDB = Depends(require_admin),
    repo = Depends(get_audit_repo),
):
    """Admin-only. Retrieve system-wide administrator audit logs."""
    return repo.list_filtered(limit=limit, username=username, action=action)
