from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from .redlab import AttemptResult, RedLabLedger


class EvaluationVerdict(str, Enum):
    FAILED = "failed"
    PARTIAL = "partial"
    SUCCESSFUL = "successful"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class CriterionFinding:
    criterion: str
    met: bool
    evidence: str

    def validate(self) -> None:
        if not self.criterion.strip():
            raise ValueError("criterion is required")
        if not self.evidence.strip():
            raise ValueError("criterion evidence is required")


@dataclass(frozen=True)
class IndependentEvaluation:
    campaign_id: str
    attempt_id: str
    evaluator: str
    verdict: EvaluationVerdict
    findings: tuple[CriterionFinding, ...]
    rationale: str
    evaluation_id: str = field(default_factory=lambda: f"evaluation-{uuid4().hex[:12]}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate(self) -> None:
        if not self.campaign_id.strip():
            raise ValueError("campaign_id is required")
        if not self.attempt_id.strip():
            raise ValueError("attempt_id is required")
        if not self.evaluator.strip():
            raise ValueError("evaluator identity is required")
        if not self.findings:
            raise ValueError("at least one criterion finding is required")
        for finding in self.findings:
            finding.validate()
        if not self.rationale.strip():
            raise ValueError("evaluation rationale is required")


@dataclass(frozen=True)
class ReplayVerification:
    campaign_id: str
    source_attempt_id: str
    replay_attempt_ids: tuple[str, ...]
    required_successes: int
    verifier: str
    verification_id: str = field(default_factory=lambda: f"verification-{uuid4().hex[:12]}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate(self) -> None:
        if not self.campaign_id.strip():
            raise ValueError("campaign_id is required")
        if not self.source_attempt_id.strip():
            raise ValueError("source_attempt_id is required")
        if not self.replay_attempt_ids:
            raise ValueError("at least one replay attempt is required")
        if len(set(self.replay_attempt_ids)) != len(self.replay_attempt_ids):
            raise ValueError("replay attempt ids must be unique")
        if self.required_successes < 1:
            raise ValueError("required_successes must be at least 1")
        if self.required_successes > len(self.replay_attempt_ids):
            raise ValueError("required_successes cannot exceed replay count")
        if not self.verifier.strip():
            raise ValueError("verifier identity is required")


class VerificationStore:
    """Append-only evaluation and replay records sharing the Red Lab JSONL ledger."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger = RedLabLedger(self.path)

    def record_evaluation(self, evaluation: IndependentEvaluation) -> IndependentEvaluation:
        evaluation.validate()
        attempt = self._find_attempt(evaluation.attempt_id)
        if attempt.campaign_id != evaluation.campaign_id:
            raise ValueError("evaluation campaign does not match attempt campaign")
        self._append(
            {
                "record_type": "evaluation",
                **asdict(evaluation),
                "verdict": evaluation.verdict.value,
            }
        )
        return evaluation

    def evaluations(self, attempt_id: str | None = None) -> list[IndependentEvaluation]:
        records: list[IndependentEvaluation] = []
        for row in self._read_rows():
            if row.get("record_type") != "evaluation":
                continue
            if attempt_id is not None and row["attempt_id"] != attempt_id:
                continue
            records.append(
                IndependentEvaluation(
                    evaluation_id=row["evaluation_id"],
                    campaign_id=row["campaign_id"],
                    attempt_id=row["attempt_id"],
                    evaluator=row["evaluator"],
                    verdict=EvaluationVerdict(row["verdict"]),
                    findings=tuple(CriterionFinding(**item) for item in row["findings"]),
                    rationale=row["rationale"],
                    created_at=row["created_at"],
                )
            )
        return records

    def record_replay(self, verification: ReplayVerification) -> dict[str, Any]:
        verification.validate()
        source = self._find_attempt(verification.source_attempt_id)
        if source.campaign_id != verification.campaign_id:
            raise ValueError("source attempt belongs to a different campaign")

        replay_attempts = [self._find_attempt(item) for item in verification.replay_attempt_ids]
        for replay in replay_attempts:
            if replay.campaign_id != verification.campaign_id:
                raise ValueError("replay attempt belongs to a different campaign")
            if replay.parent_attempt_id != verification.source_attempt_id:
                raise ValueError(
                    f"replay attempt {replay.attempt_id} must name the source attempt as parent"
                )

        successes = sum(item.result == AttemptResult.SUCCESSFUL for item in replay_attempts)
        passed = successes >= verification.required_successes
        record = {
            "record_type": "replay_verification",
            **asdict(verification),
            "successes": successes,
            "replays": len(replay_attempts),
            "passed": passed,
        }
        self._append(record)
        return record

    def replay_verifications(self, source_attempt_id: str | None = None) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for row in self._read_rows():
            if row.get("record_type") != "replay_verification":
                continue
            if source_attempt_id is not None and row["source_attempt_id"] != source_attempt_id:
                continue
            records.append(row)
        return records

    def confirmed_success(self, attempt_id: str) -> bool:
        evaluations = self.evaluations(attempt_id)
        evaluator_success = any(item.verdict == EvaluationVerdict.SUCCESSFUL for item in evaluations)
        replay_success = any(
            bool(item.get("passed")) for item in self.replay_verifications(attempt_id)
        )
        return evaluator_success and replay_success

    def _find_attempt(self, attempt_id: str):
        for attempt in self.ledger.attempts():
            if attempt.attempt_id == attempt_id:
                return attempt
        raise ValueError(f"unknown attempt_id: {attempt_id}")

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
