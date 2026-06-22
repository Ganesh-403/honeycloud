"""
Report routes (admin-only):
  POST /api/v1/reports/generate  – generate CSV / XLSX / TXT
  GET  /api/v1/reports/download  – download a generated file
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_event_service, get_report_service, get_audit_repo
from app.db.session import get_db
from app.core.security import require_admin
from app.schemas.auth import UserInDB
from app.schemas.stats import ReportResponse
from app.services.event_service import EventService
from app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/generate", response_model=ReportResponse, summary="Generate attack report")
def generate_report(
    request: Request,
    fmt: str = Query(default="csv", pattern="^(csv|xlsx|txt|pdf)$"),
    send_telegram: bool = Query(default=False),
    current_user: UserInDB = Depends(require_admin),
    svc: EventService = Depends(get_event_service),
    report_svc: ReportService = Depends(get_report_service),
    db: Session = Depends(get_db),
):
    """Admin-only. Generates a report file and optionally sends it via Telegram."""
    events = svc.get_all_events()
    stats  = svc.get_stats()
    path   = report_svc.generate(events, stats, fmt=fmt)  # type: ignore[arg-type]

    if send_telegram:
        from app.services.alert_service import AlertService
        AlertService().send_file(str(path), caption=f"HoneyCloud {fmt.upper()} Report")

    # Log action to audit trail
    client_ip = request.client.host if request.client else "0.0.0.0"
    get_audit_repo(db).log(
        username=current_user.username,
        action="GENERATE_REPORT",
        client_ip=client_ip,
        target=path.name,
        description=f"Generated {fmt.upper()} attack report with {len(events)} events (send_telegram={send_telegram}).",
    )

    return ReportResponse(
        status="success",
        message=f"{fmt.upper()} report generated",
        filepath=str(path),
        events_count=len(events),
        download_url=f"/api/v1/reports/download?file={path.name}",
    )


@router.get("/download", summary="Download a generated report")
def download_report(
    file: str = Query(..., description="Report filename (basename only)"),
    report_svc: ReportService = Depends(get_report_service),
):
    """
    Serve a generated report file.
    Path-traversal is prevented by safe_path().
    """
    try:
        resolved = report_svc.safe_path(file)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename.")

    if not resolved.exists():
        raise HTTPException(status_code=404, detail="Report not found.")

    media_types = {
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".csv":  "text/csv",
        ".txt":  "text/plain",
        ".pdf":  "application/pdf",
    }
    media_type = media_types.get(resolved.suffix, "application/octet-stream")
    return FileResponse(str(resolved), media_type=media_type, filename=file)
