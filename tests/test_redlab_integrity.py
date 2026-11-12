from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from agent_prompt_shield.redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope
from agent_prompt_shield.redlab_drafts import DraftStore
from agent_prompt_shield.redlab_strategy import StrategyAction, StrategyProposal
from agent_prompt_shield.redlab_verify import (
    CriterionFinding,
    EvaluationVerdict,
    IndependentEvaluation,
    ReplayVerification,
    VerificationStore,
)


def _seed(path: Path) -> tuple[RedLabLedger, Campaign, Attempt]:
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(
        Campaign(
            name="Integrity test",
            scope=Scope(
                target="local target",
                authorization="owner-authorized",
                allowed_actions=("submit controlled prompts",),
                prohibited_actions=("access third-party data",),
            ),
            objective="Exercise ledger invariants",
            success_criteria=("criterion one",),
        )
    )
    attempt = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="test",
            hypothesis="test hypothesis",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.SUCCESSFUL,
        )
    )
    return ledger, campaign, attempt


def _append(path: Path, row: dict) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def test_public_writes_reject_duplicate_primary_ids(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger, campaign, attempt = _seed(path)

    with pytest.raises(ValueError, match="duplicate campaign_id"):
        ledger.create_campaign(campaign)
    with pytest.raises(ValueError, match="duplicate attempt_id"):
        ledger.record_attempt(attempt)

    store = VerificationStore(path)
    evaluation = IndependentEvaluation(
        campaign_id=campaign.campaign_id,
        attempt_id=attempt.attempt_id,
        evaluator="reviewer",
        verdict=EvaluationVerdict.SUCCESSFUL,
        findings=(CriterionFinding("criterion one", True, "transcript evidence"),),
        rationale="Criterion met.",
        evaluation_id="evaluation-fixed",
    )
    store.record_evaluation(evaluation)
    with pytest.raises(ValueError, match="duplicate evaluation_id"):
        store.record_evaluation(evaluation)

    replay = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="test",
            hypothesis="replay",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.SUCCESSFUL,
            parent_attempt_id=attempt.attempt_id,
        )
    )
    verification = ReplayVerification(
        campaign_id=campaign.campaign_id,
        source_attempt_id=attempt.attempt_id,
        replay_attempt_ids=(replay.attempt_id,),
        required_successes=1,
        verifier="reviewer",
        verification_id="verification-fixed",
    )
    store.record_replay(verification)
    with pytest.raises(ValueError, match="duplicate verification_id"):
        store.record_replay(verification)


def test_read_rejects_duplicate_drafts_and_unknown_updates(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger, campaign, attempt = _seed(path)
    store = DraftStore(path)
    store.create_drafts(
        campaign_id=campaign.campaign_id,
        analysis="One scoped change.",
        proposals=(
            StrategyProposal(
                title="Scoped retry",
                action=StrategyAction.RETRY,
                attack_family="test",
                hypothesis="retry",
                controlled_change="fresh session",
                proposed_payload="payload",
                expected_signal="same response",
                stop_condition="one replay",
                parent_attempt_id=attempt.attempt_id,
                action_tags=("submit-controlled-prompts",),
            ),
        ),
    )
    rows = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    draft_row = next(row for row in rows if row["record_type"] == "strategy_draft")
    _append(path, draft_row)
    with pytest.raises(ValueError, match="duplicate draft_id in ledger"):
        store.drafts()

    other_path = tmp_path / "unknown-update.jsonl"
    _append(
        other_path,
        {
            "record_type": "attempt_update",
            "attempt_id": "attempt-missing",
            "result": "failed",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )
    with pytest.raises(ValueError, match="references unknown attempt"):
        RedLabLedger(other_path).attempts()


def test_read_rejects_duplicate_attempts_and_updates(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger, _campaign, attempt = _seed(path)
    attempt_row = next(
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if '"record_type": "attempt"' in line
    )
    _append(path, attempt_row)
    with pytest.raises(ValueError, match="duplicate attempt_id in ledger"):
        ledger.attempts()

    update_path = tmp_path / "duplicate-update.jsonl"
    update_ledger, _campaign, pending = _seed(update_path)
    # Replace the successful seed with a pending value while retaining its identity.
    rows = [json.loads(line) for line in update_path.read_text(encoding="utf-8").splitlines()]
    rows[-1]["result"] = "invalid"
    update_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )
    update_ledger.complete_attempt(
        pending.attempt_id,
        result=AttemptResult.FAILED,
        target_response="No effect.",
    )
    update_row = json.loads(update_path.read_text(encoding="utf-8").splitlines()[-1])
    _append(update_path, update_row)
    with pytest.raises(ValueError, match="duplicate attempt_update in ledger"):
        update_ledger.attempts()


def test_read_rejects_forged_replay_summary(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger, campaign, source = _seed(path)
    replay = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="test",
            hypothesis="replay",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.FAILED,
            parent_attempt_id=source.attempt_id,
        )
    )
    verification = ReplayVerification(
        campaign_id=campaign.campaign_id,
        source_attempt_id=source.attempt_id,
        replay_attempt_ids=(replay.attempt_id,),
        required_successes=1,
        verifier="reviewer",
    )
    row = {
        "record_type": "replay_verification",
        **asdict(verification),
        "successes": 1,
        "replays": 1,
        "passed": True,
    }
    _append(path, row)

    with pytest.raises(ValueError, match="summary does not match ledger"):
        VerificationStore(path).replay_verifications()
