from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .models import EnforcementResult, ScanResult


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    payload: dict[str, Any]
    event_id: str = field(default_factory=lambda: uuid4().hex)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "created_at": self.created_at,
            "event_type": self.event_type,
            "payload": self.payload,
        }


class AuditLog:
    """Append-only JSONL audit sink for scan and enforcement decisions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(self, event: AuditEvent) -> AuditEvent:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        return event

    def record_scan(
        self,
        scan: ScanResult,
        *,
        source: str = "unknown",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        return self.record(
            AuditEvent(
                event_type="scan",
                payload={
                    "source": source,
                    "scan": scan.to_dict(),
                    "metadata": metadata or {},
                },
            )
        )

    def record_enforcement(
        self,
        result: EnforcementResult,
        *,
        source: str = "unknown",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        return self.record(
            AuditEvent(
                event_type="enforcement",
                payload={
                    "source": source,
                    "scan": result.scan.to_dict(),
                    "decision": result.decision.to_dict(),
                    "metadata": metadata or {},
                },
            )
        )
