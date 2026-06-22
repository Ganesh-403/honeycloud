"""
SQLAlchemy ORM model for Report.
Maps to the 'reports' table.
Records metadata for generated PDF, CSV, and Excel reports.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.db.session import Base


class Report(Base):
    """Persists metadata for generated reports (PDF, CSV, Excel)."""

    __tablename__ = "reports"

    id            = Column(Integer, primary_key=True, index=True, autoincrement=True)

    report_type   = Column(String(20),  nullable=False, index=True)   # PDF | CSV | EXCEL
    filename      = Column(String(255), nullable=False)
    file_size     = Column(Integer,     nullable=True)                 # bytes
    record_count  = Column(Integer,     nullable=True)                 # rows in report

    generated_by  = Column(String(255), nullable=False, index=True)    # username
    description   = Column(Text,        nullable=True)

    generated_at  = Column(DateTime(timezone=True),
                           default=lambda: datetime.now(timezone.utc),
                           index=True, nullable=False)

    def __repr__(self) -> str:
        return f"<Report id={self.id} type={self.report_type} by={self.generated_by}>"
