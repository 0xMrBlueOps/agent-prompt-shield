from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from .redlab import Attempt, AttemptResult, RedLabLedger
from .redlab_strategy import StrategyAction, StrategyProposal


class DraftStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class StrategyDraft:
    campaign_id: str
    analysis: str
    proposal: StrategyProposal
    status: DraftStatus = DraftStatus.PENDING
    draft_id: str = field(default_factory=lambda: f"draft-{uuid4().hex[:12]}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate(self) -> None:
        if not self.campaign_id.strip():
            raise ValueError("campaign_id is required")
        if not self.analysis.strip():
            raise ValueError("strategy analysis is required")
        self.proposal.validate()


class DraftStore:
    """Append-only strategy proposal workflow sharing the Red Lab JSONL ledger."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger = RedLabLedger(self.path)

    def create_drafts(
        self,
        *,
        campaign_id: str,
        analysis: str,
        proposals: tuple[StrategyProposal, ...],
    ) -> tuple[StrategyDraft, ...]:
        campaign_ids = {item.campaign_id for item in self.ledger.campaigns()}
        if campaign_id not in campaign_ids:
            raise ValueError(f"unknown campaign_id: {campaign_id}")
        attempt_ids = {item.attempt_id for item in self.ledger.attempts(campaign_id)}
        drafts: list[StrategyDraft] = []
        for proposal in proposals:
            if proposal.parent_attempt_id not in attempt_ids:
                raise ValueError(
                    f"proposal references unknown parent attempt: {proposal.parent_attempt_id}"
                )
            draft = StrategyDraft(
                campaign_id=campaign_id,
                analysis=analysis,
                proposal=proposal,
            )
            draft.validate()
            self._append(
                {
                    "record_type": "strategy_draft",
                    **asdict(draft),
                    "status": draft.status.value,
                    "proposal": {
                        **asdict(proposal),
                        "action": proposal.action.value,
                    },
                }
            )
            drafts.append(draft)
        return tuple(drafts)

    def drafts(
        self,
        *,
        campaign_id: str | None = None,
        status: DraftStatus | None = None,
    ) -> list[StrategyDraft]:
        latest: dict[str, StrategyDraft] = {}
        for row in self._read_rows():
            record_type = row.get("record_type")
            if record_type == "strategy_draft":
                draft = self._draft_from_row(row)
                latest[draft.draft_id] = draft
            elif record_type == "strategy_draft_status":
                draft_id = row["draft_id"]
                current = latest.get(draft_id)
                if current is None:
                    continue
                latest[draft_id] = StrategyDraft(
                    draft_id=current.draft_id,
                    campaign_id=current.campaign_id,
                    analysis=current.analysis,
                    proposal=current.proposal,
                    status=DraftStatus(row["status"]),
                    created_at=current.created_at,
                )
        items = list(latest.values())
        if campaign_id is not None:
            items = [item for item in items if item.campaign_id == campaign_id]
        if status is not None:
            items = [item for item in items if item.status == status]
        return sorted(items, key=lambda item: item.created_at)

    def accept(self, draft_id: str, *, delivery_channel: str) -> Attempt:
        draft = self._find_pending(draft_id)
        if draft.proposal.action == StrategyAction.STOP:
            raise ValueError("STOP proposals cannot be accepted as attempts")
        if not delivery_channel.strip():
            raise ValueError("delivery_channel is required")
        attempt = self.ledger.record_attempt(
            Attempt(
                campaign_id=draft.campaign_id,
                attack_family=draft.proposal.attack_family,
                hypothesis=draft.proposal.hypothesis,
                payload=draft.proposal.proposed_payload,
                delivery_channel=delivery_channel,
                result=AttemptResult.INVALID,
                parent_attempt_id=draft.proposal.parent_attempt_id,
                lesson=(
                    "Draft accepted before execution. Controlled change: "
                    f"{draft.proposal.controlled_change}. Expected signal: "
                    f"{draft.proposal.expected_signal}. Stop condition: "
                    f"{draft.proposal.stop_condition}"
                ),
            )
        )
        self._record_status(draft_id, DraftStatus.ACCEPTED, attempt_id=attempt.attempt_id)
        return attempt

    def reject(self, draft_id: str, *, reason: str) -> StrategyDraft:
        draft = self._find_pending(draft_id)
        if not reason.strip():
            raise ValueError("rejection reason is required")
        self._record_status(draft_id, DraftStatus.REJECTED, reason=reason)
        return StrategyDraft(
            draft_id=draft.draft_id,
            campaign_id=draft.campaign_id,
            analysis=draft.analysis,
            proposal=draft.proposal,
            status=DraftStatus.REJECTED,
            created_at=draft.created_at,
        )

    def _find_pending(self, draft_id: str) -> StrategyDraft:
        for item in self.drafts():
            if item.draft_id == draft_id:
                if item.status != DraftStatus.PENDING:
                    raise ValueError(f"draft is already {item.status.value}")
                return item
        raise ValueError(f"unknown draft_id: {draft_id}")

    def _record_status(
        self,
        draft_id: str,
        status: DraftStatus,
        **metadata: Any,
    ) -> None:
        self._append(
            {
                "record_type": "strategy_draft_status",
                "draft_id": draft_id,
                "status": status.value,
                "created_at": datetime.now(timezone.utc).isoformat(),
                **metadata,
            }
        )

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
    def _draft_from_row(row: dict[str, Any]) -> StrategyDraft:
        proposal = row["proposal"]
        return StrategyDraft(
            draft_id=row["draft_id"],
            campaign_id=row["campaign_id"],
            analysis=row["analysis"],
            proposal=StrategyProposal(
                title=proposal["title"],
                action=StrategyAction(proposal["action"]),
                attack_family=proposal["attack_family"],
                hypothesis=proposal["hypothesis"],
                controlled_change=proposal["controlled_change"],
                proposed_payload=proposal["proposed_payload"],
                expected_signal=proposal["expected_signal"],
                stop_condition=proposal["stop_condition"],
                parent_attempt_id=proposal["parent_attempt_id"],
            ),
            status=DraftStatus(row["status"]),
            created_at=row["created_at"],
        )
