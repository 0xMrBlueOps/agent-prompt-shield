from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from .redlab import Attempt, AttemptResult, Campaign, RedLabLedger


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
        if not self.evaluation_id.strip():
            raise ValueError("evaluation_id is required")
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
        if not self.verification_id.strip():
            raise ValueError("verification_id is required")
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
        campaign = self._find_campaign(evaluation.campaign_id)
        _validate_evaluation_criteria(evaluation, campaign.success_criteria)
        if evaluation.evaluation_id in {item.evaluation_id for item in self.evaluations()}:
            raise ValueError(f"duplicate evaluation_id: {evaluation.evaluation_id}")
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
        seen: set[str] = set()
        for row in self._read_rows():
            if row.get("record_type") != "evaluation":
                continue
            evaluation_id = row["evaluation_id"]
            if evaluation_id in seen:
                raise ValueError(f"duplicate evaluation_id in ledger: {evaluation_id}")
            seen.add(evaluation_id)
            item = IndependentEvaluation(
                evaluation_id=evaluation_id,
                campaign_id=row["campaign_id"],
                attempt_id=row["attempt_id"],
                evaluator=row["evaluator"],
                verdict=EvaluationVerdict(row["verdict"]),
                findings=tuple(CriterionFinding(**finding) for finding in row["findings"]),
                rationale=row["rationale"],
                created_at=row["created_at"],
            )
            item.validate()
            attempt = self._find_attempt(item.attempt_id)
            if attempt.campaign_id != item.campaign_id:
                raise ValueError("evaluation campaign does not match attempt campaign")
            campaign = self._find_campaign(item.campaign_id)
            _validate_evaluation_criteria(item, campaign.success_criteria)
            if attempt_id is None or item.attempt_id == attempt_id:
                records.append(item)
        return records

    def record_replay(self, verification: ReplayVerification) -> dict[str, Any]:
        verification.validate()
        if verification.verification_id in {
            item["verification_id"] for item in self.replay_verifications()
        }:
            raise ValueError(f"duplicate verification_id: {verification.verification_id}")
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
        seen: set[str] = set()
        for row in self._read_rows():
            if row.get("record_type") != "replay_verification":
                continue
            verification_id = row["verification_id"]
            if verification_id in seen:
                raise ValueError(f"duplicate verification_id in ledger: {verification_id}")
            seen.add(verification_id)
            self._validate_replay_record(row)
            if source_attempt_id is None or row["source_attempt_id"] == source_attempt_id:
                records.append(row)
        return records

    def confirmed_success(self, attempt_id: str) -> bool:
        source = self._find_attempt(attempt_id)
        if source.result != AttemptResult.SUCCESSFUL:
            return False
        campaign = self._find_campaign(source.campaign_id)
        evaluations = self.evaluations(attempt_id)
        evaluator_success = any(
            item.campaign_id == campaign.campaign_id
            and item.verdict == EvaluationVerdict.SUCCESSFUL
            and all(finding.met and finding.evidence.strip() for finding in item.findings)
            for item in evaluations
        )
        replay_success = any(
            bool(item.get("passed")) for item in self.replay_verifications(attempt_id)
        )
        return evaluator_success and replay_success

    def _find_attempt(self, attempt_id: str) -> Attempt:
        return self.ledger.get_attempt(attempt_id)

    def _find_campaign(self, campaign_id: str) -> Campaign:
        for campaign in self.ledger.campaigns():
            if campaign.campaign_id == campaign_id:
                return campaign
        raise ValueError(f"unknown campaign_id: {campaign_id}")

    def _validate_replay_record(self, row: dict[str, Any]) -> None:
        verification = ReplayVerification(
            campaign_id=row["campaign_id"],
            source_attempt_id=row["source_attempt_id"],
            replay_attempt_ids=tuple(row["replay_attempt_ids"]),
            required_successes=row["required_successes"],
            verifier=row["verifier"],
            verification_id=row["verification_id"],
            created_at=row["created_at"],
        )
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
        if row.get("successes") != successes or row.get("replays") != len(replay_attempts):
            raise ValueError(
                f"replay verification summary does not match ledger: {verification.verification_id}"
            )
        if row.get("passed") is not passed:
            raise ValueError(
                f"replay verification outcome does not match ledger: {verification.verification_id}"
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


def _validate_evaluation_criteria(
    evaluation: IndependentEvaluation,
    success_criteria: tuple[str, ...],
) -> None:
    finding_criteria = tuple(item.criterion for item in evaluation.findings)
    if finding_criteria != success_criteria:
        raise ValueError(
            "evaluation findings must match campaign success criteria exactly and in order"
        )
    met = tuple(item.met for item in evaluation.findings)
    if evaluation.verdict == EvaluationVerdict.SUCCESSFUL and not all(met):
        raise ValueError("successful evaluation requires every criterion to be met")
    if evaluation.verdict == EvaluationVerdict.FAILED and any(met):
        raise ValueError("failed evaluation cannot contain met criteria")
    if evaluation.verdict == EvaluationVerdict.PARTIAL and (not any(met) or all(met)):
        raise ValueError("partial evaluation requires both met and unmet criteria")
