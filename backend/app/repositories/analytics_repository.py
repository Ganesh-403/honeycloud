"""
AnalyticsRepository – pre-aggregated queries for the analytics dashboard.
All methods return plain dicts/lists (not ORM objects) so they can be
serialised directly by Pydantic response models.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Float, Integer, cast, func, select, text
from sqlalchemy.orm import Session

from app.models.attack_event import AttackEvent


class AnalyticsRepository:
    def __init__(self, db: Session):
        self.db = db

    # ── Timeline ──────────────────────────────────────────────────────────────

    def hourly_timeline(self, hours: int = 24) -> list[dict]:
        """Events per hour for the last N hours."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)

        # SQLite-compatible hour truncation via strftime
        rows = self.db.execute(
            text("""
                SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) AS hour_bucket,
                       COUNT(*) AS event_count,
                       SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
                       SUM(CASE WHEN severity = 'HIGH'     THEN 1 ELSE 0 END) AS high_count
                FROM attack_events
                WHERE timestamp >= :since
                GROUP BY hour_bucket
                ORDER BY hour_bucket ASC
            """),
            {"since": since.isoformat()},
        ).fetchall()

        return [
            {
                "bucket": row[0],
                "total": row[1],
                "critical": row[2],
                "high": row[3],
            }
            for row in rows
        ]

    def daily_timeline(self, days: int = 30) -> list[dict]:
        """Events per day for the last N days."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        rows = self.db.execute(
            text("""
                SELECT strftime('%Y-%m-%d', timestamp) AS day_bucket,
                       COUNT(*) AS event_count,
                       SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) AS severe_count,
                       COUNT(DISTINCT source_ip) AS unique_ips
                FROM attack_events
                WHERE timestamp >= :since
                GROUP BY day_bucket
                ORDER BY day_bucket ASC
            """),
            {"since": since.isoformat()},
        ).fetchall()

        return [
            {
                "bucket": row[0],
                "total": row[1],
                "severe": row[2],
                "unique_ips": row[3],
            }
            for row in rows
        ]

    # ── Geographic distribution ───────────────────────────────────────────────

    def geo_distribution(self) -> list[dict]:
        """
        Aggregate events by country using the stored geolocation JSON.
        Returns top 50 countries sorted by event count.
        """
        rows = self.db.execute(
            text("""
                SELECT
                    json_extract(geolocation, '$.country')      AS country,
                    json_extract(geolocation, '$.country_code') AS country_code,
                    json_extract(geolocation, '$.flag')         AS flag,
                    COUNT(*) AS event_count,
                    COUNT(DISTINCT source_ip) AS unique_ips
                FROM attack_events
                WHERE geolocation IS NOT NULL
                  AND json_extract(geolocation, '$.country_code') != 'XX'
                GROUP BY country_code
                ORDER BY event_count DESC
                LIMIT 50
            """)
        ).fetchall()

        return [
            {
                "country": row[0] or "Unknown",
                "country_code": row[1] or "XX",
                "flag": row[2] or "🌍",
                "event_count": row[3],
                "unique_ips": row[4],
            }
            for row in rows
        ]

    # ── Attack heatmap ────────────────────────────────────────────────────────

    def attack_heatmap(self) -> list[dict]:
        """
        Returns a 24×7 matrix: events by hour-of-day × day-of-week.
        Useful for spotting 'when do attacks peak' patterns.
        """
        rows = self.db.execute(
            text("""
                SELECT
                    CAST(strftime('%H', timestamp) AS INTEGER) AS hour_of_day,
                    CAST(strftime('%w', timestamp) AS INTEGER) AS day_of_week,
                    COUNT(*) AS count
                FROM attack_events
                GROUP BY hour_of_day, day_of_week
                ORDER BY day_of_week, hour_of_day
            """)
        ).fetchall()

        return [
            {"hour": row[0], "day": row[1], "count": row[2]}
            for row in rows
        ]

    # ── Credential analysis ───────────────────────────────────────────────────

    def top_usernames(self, limit: int = 15) -> list[dict]:
        rows = self.db.execute(
            text("""
                SELECT username, COUNT(*) AS attempts,
                       COUNT(DISTINCT source_ip) AS unique_sources
                FROM attack_events
                WHERE username IS NOT NULL AND username != ''
                GROUP BY username
                ORDER BY attempts DESC
                LIMIT :limit
            """),
            {"limit": limit},
        ).fetchall()
        return [{"username": r[0], "attempts": r[1], "unique_sources": r[2]} for r in rows]

    def top_passwords(self, limit: int = 15) -> list[dict]:
        rows = self.db.execute(
            text("""
                SELECT password, COUNT(*) AS attempts,
                       COUNT(DISTINCT source_ip) AS unique_sources
                FROM attack_events
                WHERE password IS NOT NULL AND password != ''
                GROUP BY password
                ORDER BY attempts DESC
                LIMIT :limit
            """),
            {"limit": limit},
        ).fetchall()
        return [{"password": r[0], "attempts": r[1], "unique_sources": r[2]} for r in rows]

    def top_commands(self, limit: int = 15) -> list[dict]:
        rows = self.db.execute(
            text("""
                SELECT command, COUNT(*) AS uses,
                       COUNT(DISTINCT source_ip) AS unique_sources,
                       service
                FROM attack_events
                WHERE command IS NOT NULL AND command != ''
                GROUP BY command
                ORDER BY uses DESC
                LIMIT :limit
            """),
            {"limit": limit},
        ).fetchall()
        return [{"command": r[0], "uses": r[1], "unique_sources": r[2], "service": r[3]} for r in rows]

    # ── Service breakdown over time ───────────────────────────────────────────

    def service_trend(self, days: int = 7) -> list[dict]:
        """Daily event counts split by service for trend charts."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        rows = self.db.execute(
            text("""
                SELECT strftime('%Y-%m-%d', timestamp) AS day,
                       service,
                       COUNT(*) AS count
                FROM attack_events
                WHERE timestamp >= :since
                GROUP BY day, service
                ORDER BY day, service
            """),
            {"since": since.isoformat()},
        ).fetchall()
        return [{"day": r[0], "service": r[1], "count": r[2]} for r in rows]

    # ── Summary stats ─────────────────────────────────────────────────────────

    def summary(self) -> dict[str, Any]:
        """Single-query summary for the analytics overview card."""
        row = self.db.execute(
            text("""
                SELECT
                    COUNT(*)                               AS total_events,
                    COUNT(DISTINCT source_ip)              AS unique_attackers,
                    SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical_total,
                    SUM(CASE WHEN ai_label='malicious' THEN 1 ELSE 0 END) AS malicious_total,
                    MAX(timestamp)                         AS latest_event,
                    AVG(threat_score)                      AS avg_threat_score
                FROM attack_events
            """)
        ).fetchone()

        if not row or row[0] == 0:
            return {
                "total_events": 0, "unique_attackers": 0,
                "critical_total": 0, "malicious_total": 0,
                "latest_event": None, "avg_threat_score": 0.0,
            }

        return {
            "total_events":      row[0],
            "unique_attackers":  row[1],
            "critical_total":    row[2],
            "malicious_total":   row[3],
            "latest_event":      row[4],
            "avg_threat_score":  round(float(row[5] or 0), 3),
        }
