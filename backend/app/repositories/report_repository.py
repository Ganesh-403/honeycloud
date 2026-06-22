"""
ReportRepository – database operations for Report model.
"""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.report import Report


class ReportRepository:
    """Encapsulates all Report DB queries."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, report_type: str, filename: str, generated_by: str,
               file_size: int = None, record_count: int = None,
               description: str = None) -> Report:
        """Log a generated report."""
        report = Report(
            report_type=report_type,
            filename=filename,
            generated_by=generated_by,
            file_size=file_size,
            record_count=record_count,
            description=description,
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        return report

    def list_recent(self, limit: int = 50) -> list[Report]:
        """Get the most recent reports."""
        return list(self.db.scalars(
            select(Report).order_by(Report.generated_at.desc()).limit(limit)
        ).all())

    def count_by_type(self) -> dict[str, int]:
        """Get count of reports per type."""
        rows = self.db.execute(
            select(Report.report_type, func.count(Report.id))
            .group_by(Report.report_type)
        ).all()
        return {row[0]: row[1] for row in rows}
