from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4


class AttemptResult(str, Enum):
    FAILED = "failed"
    PARTIAL = "partial"
    SUCCESSFUL = "successful"
    INVALID = "invalid"


@dataclass(frozen=True)
class Scope:
    """Declared authorization boundary for one red-team campaign."""

    target: str
    authorization: str
    allowed_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...] = ()
    disclosure_requirements: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.target.strip():
            raise ValueError("scope target is required")
        if not self.authorization.strip():
            raise ValueError("scope authorization is required")
        if not self.allowed_actions:
            raise ValueError("scope must declare at least one allowed action")


@dataclass(frozen=True)
class Campaign:
    name: str
    scope: Scope
    objective: str
    success_criteria: tuple[str, ...]
    campaign_id: str = field(default_factory=lambda: f"campaign-{uuid4().hex[:12]}")
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate(self) -> None:
        self.scope.validate()
        if not self.name.strip():
            raise ValueError("campaign name is required")
        if not self.objective.strip():
            raise ValueError("campaign objective is required")
        if not self.success_criteria:
            raise ValueError("campaign must define success criteria")


@dataclass(frozen=True)
class Attempt:
    campaign_id: str
    attack_family: str
    hypothesis: str
    payload: str
    delivery_channel: str
    result: AttemptResult
    target_response: str = ""
    tool_trace: tuple[dict[str, Any], ...] = ()
    failure_reason: str = ""
    lesson: str = ""
    parent_attempt_id: str | None = None
    attempt_id: str = field(default_factory=lambda: f"attempt-{uuid4().hex[:12]}")
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate(self) -> None:
        required = {
            "campaign_id": self.campaign_id,
            "attack_family": self.attack_family,
            "hypothesis": self.hypothesis,
            "delivery_channel": self.delivery_channel,
        }
        missing = [name for name, value in required.items() if not value.strip()]
        if missing:
            raise ValueError(f"attempt missing required fields: {', '.join(missing)}")


class RedLabLedger:
    """Append-only JSONL store for authorized adversarial experiments."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def create_campaign(self, campaign: Campaign) -> Campaign:
        campaign.validate()
        self._append({"record_type": "campaign", **asdict(campaign)})
        return campaign

    def record_attempt(self, attempt: Attempt) -> Attempt:
        attempt.validate()
        campaign_ids = {campaign.campaign_id for campaign in self.campaigns()}
        if attempt.campaign_id not in campaign_ids:
            raise ValueError(f"unknown campaign_id: {attempt.campaign_id}")
        if attempt.parent_attempt_id is not None:
            attempt_ids = {item.attempt_id for item in self.attempts(attempt.campaign_id)}
            if attempt.parent_attempt_id not in attempt_ids:
                raise ValueError(f"unknown parent_attempt_id: {attempt.parent_attempt_id}")
        self._append({"record_type": "attempt", **self._attempt_dict(attempt)})
        return attempt

    def campaigns(self) -> list[Campaign]:
        records: list[Campaign] = []
        for row in self._read_rows():
            if row.get("record_type") != "campaign":
                continue
            scope_data = row["scope"]
            records.append(
                Campaign(
                    campaign_id=row["campaign_id"],
                    name=row["name"],
                    objective=row["objective"],
                    success_criteria=tuple(row["success_criteria"]),
                    created_at=row["created_at"],
                    scope=Scope(
                        target=scope_data["target"],
                        authorization=scope_data["authorization"],
                        allowed_actions=tuple(scope_data["allowed_actions"]),
                        prohibited_actions=tuple(scope_data.get("prohibited_actions", ())),
                        disclosure_requirements=tuple(
                            scope_data.get("disclosure_requirements", ())
                        ),
                    ),
                )
            )
        return records

    def attempts(self, campaign_id: str | None = None) -> list[Attempt]:
        records: list[Attempt] = []
        for row in self._read_rows():
            if row.get("record_type") != "attempt":
                continue
            if campaign_id is not None and row["campaign_id"] != campaign_id:
                continue
            records.append(
                Attempt(
                    attempt_id=row["attempt_id"],
                    campaign_id=row["campaign_id"],
                    attack_family=row["attack_family"],
                    hypothesis=row["hypothesis"],
                    payload=row["payload"],
                    delivery_channel=row["delivery_channel"],
                    result=AttemptResult(row["result"]),
                    target_response=row.get("target_response", ""),
                    tool_trace=tuple(row.get("tool_trace", ())),
                    failure_reason=row.get("failure_reason", ""),
                    lesson=row.get("lesson", ""),
                    parent_attempt_id=row.get("parent_attempt_id"),
                    created_at=row["created_at"],
                )
            )
        return records

    def metrics(self, campaign_id: str) -> dict[str, float | int]:
        attempts = [a for a in self.attempts(campaign_id) if a.result != AttemptResult.INVALID]
        total = len(attempts)
        successes = sum(a.result == AttemptResult.SUCCESSFUL for a in attempts)
        partials = sum(a.result == AttemptResult.PARTIAL for a in attempts)
        return {
            "attempts": total,
            "successes": successes,
            "partials": partials,
            "failures": sum(a.result == AttemptResult.FAILED for a in attempts),
            "attack_success_rate": successes / total if total else 0.0,
            "partial_or_better_rate": (successes + partials) / total if total else 0.0,
        }

    def attempt_tree(self, campaign_id: str) -> dict[str | None, list[Attempt]]:
        tree: dict[str | None, list[Attempt]] = {}
        for attempt in self.attempts(campaign_id):
            tree.setdefault(attempt.parent_attempt_id, []).append(attempt)
        return tree

    def _append(self, row: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    def _read_rows(self) -> Iterable[dict[str, Any]]:
        if not self.path.exists():
            return ()
        rows: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"invalid JSONL at {self.path}:{line_number}: {exc.msg}"
                    ) from exc
        return rows

    @staticmethod
    def _attempt_dict(attempt: Attempt) -> dict[str, Any]:
        row = asdict(attempt)
        row["result"] = attempt.result.value
        return row
