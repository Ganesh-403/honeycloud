"""
EventService – core business logic for attack event lifecycle.
Orchestrates: ingest → enrich → classify → persist → [background] profile + alert + broadcast.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import BackgroundTasks

from app.core.logging import get_logger
from app.models.attack_event import AttackEvent
from app.repositories.event_repository import EventRepository
from app.schemas.event import EventFilters, EventIngest
from app.schemas.stats import StatsResponse
from app.services.alert_service import AlertService
from app.services.geo_service import lookup_location, resolve_ip
from app.ml.detector import MLThreatDetector

logger = get_logger(__name__)


class EventService:
    def __init__(
        self,
        repo: EventRepository,
        alert_svc: AlertService,
        detector: MLThreatDetector,
    ):
        self._repo = repo
        self._alert = alert_svc
        self._ml = detector

    def ingest(
        self,
        payload: EventIngest,
        source_ip: str,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> AttackEvent:
        resolved_ip = resolve_ip(source_ip)
        location = lookup_location(resolved_ip)

        event_dict = payload.model_dump()
        prediction = self._ml.predict(event_dict)
        if prediction["label"] != "unknown":
            event_dict["ai_label"] = prediction["label"]
            event_dict["threat_score"] = prediction["score"]

        record_data: dict[str, Any] = {
            **event_dict,
            "source_ip": resolved_ip,
            "timestamp": payload.timestamp or datetime.now(timezone.utc),
            "geolocation": location.model_dump(),
            "meta_data": payload.metadata,
        }
        record_data.pop("metadata", None)

        event = self._repo.create(record_data)
        logger.info(
            "Event ingested | id=%d service=%s ip=%s severity=%s label=%s",
            event.id, event.service, event.source_ip, event.severity, event.ai_label,
        )

        if background_tasks:
            background_tasks.add_task(self._background_profile, event.source_ip, event.id)
            if event.severity in ("CRITICAL", "HIGH"):
                background_tasks.add_task(self._alert.dispatch, event)
            background_tasks.add_task(self._broadcast_event, event)
        else:
            if event.severity in ("CRITICAL", "HIGH"):
                self._alert.dispatch(event)

        return event

    def _background_profile(self, ip: str, event_id: int) -> None:
        from app.db.session import SessionLocal
        from app.services.profiler_service import ProfilerService
        db = SessionLocal()
        try:
            event = db.get(AttackEvent, event_id)
            if event:
                ProfilerService(db).process_event(event)
        except Exception as exc:
            logger.error("Background profile update failed ip=%s: %s", ip, exc)
        finally:
            db.close()

    def _broadcast_event(self, event: AttackEvent) -> None:
        from app.core.websocket_manager import ws_manager
        if ws_manager.connection_count == 0:
            return
        payload = {
            "type": "new_attack",
            "data": {
                "id": event.id,
                "timestamp": str(event.timestamp),
                "service": event.service,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "ai_label": event.ai_label,
                "threat_score": event.threat_score,
                "username": event.username,
                "command": event.command,
                "geolocation": event.geolocation or {},
            },
        }
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(ws_manager.broadcast(payload))
            else:
                loop.run_until_complete(ws_manager.broadcast(payload))
        except RuntimeError:
            asyncio.run(ws_manager.broadcast(payload))

    def list_events(self, filters: EventFilters) -> list[AttackEvent]:
        return self._repo.list_filtered(filters)

    def get_stats(self) -> StatsResponse:
        return StatsResponse(
            total_events=self._repo.count_all(),
            events_by_service=self._repo.count_by_service(),
            events_by_severity=self._repo.count_by_severity(),
            ai_labels=self._repo.count_by_ai_label(),
            last_updated=datetime.now(timezone.utc),
        )

    def get_all_events(self) -> list[AttackEvent]:
        return self._repo.get_all()

    def simulate(self, source_ip: str, count: int = 30) -> dict:
        import random
        TEMPLATES = [
            ("root",      "CRITICAL", "malicious", 0.95, "rm -rf /",       "SSH"),
            ("admin",     "CRITICAL", "malicious", 0.93, "cat /etc/shadow","SSH"),
            ("admin",     "HIGH",     "malicious", 0.85, "sudo su",        "SSH"),
            ("root",      "HIGH",     "anomaly",   0.82, "netstat -tulpn", "HTTP"),
            ("user",      "MEDIUM",   "anomaly",   0.65, "ls -la /root",   "SSH"),
            ("guest",     "MEDIUM",   "anomaly",   0.63, "whoami",         "HTTP"),
            ("anonymous", "LOW",      "benign",    0.35, "help",           "FTP"),
            ("visitor",   "LOW",      "benign",    0.30, "ls",             "HTTP"),
        ]
        created: list[AttackEvent] = []
        for _ in range(count):
            username, severity, label, score, cmd, service = random.choice(TEMPLATES)
            p = EventIngest(
                source_ip=source_ip,
                source_port=random.randint(1024, 65535),
                service=service, username=username,
                password=f"pass{random.randint(1000, 9999)}",
                command=cmd, severity=severity,
                ai_label=label, threat_score=score,
            )
            event = self.ingest(p, source_ip)
            created.append(event)

        breakdown = {s: sum(1 for e in created if e.severity == s)
                     for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        logger.info("Simulation: %d events from %s", count, source_ip)
        return {
            "status": "success",
            "message": f"Generated {count} attacks from {source_ip}",
            "attacker_ip": source_ip,
            "total_new": len(created),
            "breakdown": breakdown,
        }
