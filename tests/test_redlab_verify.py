import pytest

from agent_prompt_shield.redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope
from agent_prompt_shield.redlab_verify import (
    CriterionFinding,
    EvaluationVerdict,
    IndependentEvaluation,
    ReplayVerification,
    VerificationStore,
)


def _campaign() -> Campaign:
    return Campaign(
        name="Authorized agent test",
        scope=Scope(
            target="local test agent",
            authorization="owner-authorized test environment",
            allowed_actions=("submit controlled prompts",),
        ),
        objective="Test instruction-boundary handling",
        success_criteria=("target performs the declared test behavior",),
    )


def test_confirmed_success_requires_evaluation_and_replay(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(_campaign())
    source = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="direct_prompt_injection",
            hypothesis="A controlled role-confusion test may affect behavior",
            payload="test payload",
            delivery_channel="chat",
            result=AttemptResult.SUCCESSFUL,
            target_response="declared behavior observed",
        )
    )
    replay_one = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="direct_prompt_injection",
            hypothesis="Replay source attempt in a fresh session",
            payload="test payload",
            delivery_channel="chat",
            result=AttemptResult.SUCCESSFUL,
            parent_attempt_id=source.attempt_id,
        )
    )
    replay_two = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="direct_prompt_injection",
            hypothesis="Second fresh-session replay",
            payload="test payload",
            delivery_channel="chat",
            result=AttemptResult.FAILED,
            parent_attempt_id=source.attempt_id,
        )
    )

    store = VerificationStore(path)
    assert not store.confirmed_success(source.attempt_id)

    store.record_evaluation(
        IndependentEvaluation(
            campaign_id=campaign.campaign_id,
            attempt_id=source.attempt_id,
            evaluator="independent-verifier",
            verdict=EvaluationVerdict.SUCCESSFUL,
            findings=(
                CriterionFinding(
                    criterion=campaign.success_criteria[0],
                    met=True,
                    evidence="The transcript contains the declared behavior.",
                ),
            ),
            rationale="The result satisfies the campaign criterion.",
        )
    )
    assert not store.confirmed_success(source.attempt_id)

    result = store.record_replay(
        ReplayVerification(
            campaign_id=campaign.campaign_id,
            source_attempt_id=source.attempt_id,
            replay_attempt_ids=(replay_one.attempt_id, replay_two.attempt_id),
            required_successes=1,
            verifier="replay-runner",
        )
    )
    assert result["passed"] is True
    assert result["successes"] == 1
    assert store.confirmed_success(source.attempt_id)


def test_replay_must_be_child_of_source_attempt(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(_campaign())
    source = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="tool_output_injection",
            hypothesis="Untrusted tool output may alter the planner",
            payload="controlled test",
            delivery_channel="tool_output",
            result=AttemptResult.PARTIAL,
        )
    )
    unrelated = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="tool_output_injection",
            hypothesis="Separate experiment",
            payload="controlled test 2",
            delivery_channel="tool_output",
            result=AttemptResult.SUCCESSFUL,
        )
    )

    store = VerificationStore(path)
    try:
        store.record_replay(
            ReplayVerification(
                campaign_id=campaign.campaign_id,
                source_attempt_id=source.attempt_id,
                replay_attempt_ids=(unrelated.attempt_id,),
                required_successes=1,
                verifier="replay-runner",
            )
        )
    except ValueError as exc:
        assert "must name the source attempt as parent" in str(exc)
    else:
        raise AssertionError("expected replay parent validation to fail")


def test_failed_or_partial_source_attempt_cannot_be_confirmed(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(_campaign())
    store = VerificationStore(path)

    for result in (AttemptResult.FAILED, AttemptResult.PARTIAL):
        source = ledger.record_attempt(
            Attempt(
                campaign_id=campaign.campaign_id,
                attack_family="test",
                hypothesis="source result gate",
                payload="payload",
                delivery_channel="local",
                result=result,
            )
        )
        replay = ledger.record_attempt(
            Attempt(
                campaign_id=campaign.campaign_id,
                attack_family="test",
                hypothesis="replay",
                payload="payload",
                delivery_channel="local",
                result=AttemptResult.SUCCESSFUL,
                parent_attempt_id=source.attempt_id,
            )
        )
        store.record_evaluation(
            IndependentEvaluation(
                campaign_id=campaign.campaign_id,
                attempt_id=source.attempt_id,
                evaluator="reviewer",
                verdict=EvaluationVerdict.SUCCESSFUL,
                findings=(
                    CriterionFinding(
                        campaign.success_criteria[0],
                        True,
                        "Evidence exists.",
                    ),
                ),
                rationale="Criterion met.",
            )
        )
        store.record_replay(
            ReplayVerification(
                campaign_id=campaign.campaign_id,
                source_attempt_id=source.attempt_id,
                replay_attempt_ids=(replay.attempt_id,),
                required_successes=1,
                verifier="reviewer",
            )
        )
        assert not store.confirmed_success(source.attempt_id)


def test_evaluation_requires_exact_criteria_and_consistent_verdict(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(
        Campaign(
            name="Two criteria",
            scope=_campaign().scope,
            objective="Strict evaluation",
            success_criteria=("criterion one", "criterion two"),
        )
    )
    attempt = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="test",
            hypothesis="strict evaluation",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.SUCCESSFUL,
        )
    )
    store = VerificationStore(path)

    cases = (
        (
            EvaluationVerdict.SUCCESSFUL,
            (CriterionFinding("criterion one", True, "evidence"),),
            "match campaign success criteria exactly",
        ),
        (
            EvaluationVerdict.SUCCESSFUL,
            (
                CriterionFinding("criterion one", True, "evidence"),
                CriterionFinding("criterion one", True, "evidence"),
            ),
            "match campaign success criteria exactly",
        ),
        (
            EvaluationVerdict.SUCCESSFUL,
            (
                CriterionFinding("criterion one", True, "evidence"),
                CriterionFinding("unexpected", True, "evidence"),
            ),
            "match campaign success criteria exactly",
        ),
        (
            EvaluationVerdict.SUCCESSFUL,
            (
                CriterionFinding("criterion one", True, "evidence"),
                CriterionFinding("criterion two", False, "evidence"),
            ),
            "requires every criterion",
        ),
        (
            EvaluationVerdict.FAILED,
            (
                CriterionFinding("criterion one", True, "evidence"),
                CriterionFinding("criterion two", False, "evidence"),
            ),
            "failed evaluation cannot contain met criteria",
        ),
        (
            EvaluationVerdict.PARTIAL,
            (
                CriterionFinding("criterion one", True, "evidence"),
                CriterionFinding("criterion two", True, "evidence"),
            ),
            "partial evaluation requires both",
        ),
    )
    for verdict, findings, message in cases:
        with pytest.raises(ValueError, match=message):
            store.record_evaluation(
                IndependentEvaluation(
                    campaign_id=campaign.campaign_id,
                    attempt_id=attempt.attempt_id,
                    evaluator="reviewer",
                    verdict=verdict,
                    findings=findings,
                    rationale="Review.",
                )
            )

    with pytest.raises(ValueError, match="criterion evidence is required"):
        store.record_evaluation(
            IndependentEvaluation(
                campaign_id=campaign.campaign_id,
                attempt_id=attempt.attempt_id,
                evaluator="reviewer",
                verdict=EvaluationVerdict.SUCCESSFUL,
                findings=(
                    CriterionFinding("criterion one", True, " "),
                    CriterionFinding("criterion two", True, "evidence"),
                ),
                rationale="Review.",
            )
        )


def test_replay_rejects_duplicate_ids_and_cross_source_links(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(_campaign())
    source = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="test",
            hypothesis="source",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.SUCCESSFUL,
        )
    )
    other_source = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="test",
            hypothesis="other source",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.SUCCESSFUL,
        )
    )
    replay = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="test",
            hypothesis="wrong source replay",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.SUCCESSFUL,
            parent_attempt_id=other_source.attempt_id,
        )
    )
    store = VerificationStore(path)

    with pytest.raises(ValueError, match="must be unique"):
        store.record_replay(
            ReplayVerification(
                campaign_id=campaign.campaign_id,
                source_attempt_id=source.attempt_id,
                replay_attempt_ids=(replay.attempt_id, replay.attempt_id),
                required_successes=1,
                verifier="reviewer",
            )
        )
    with pytest.raises(ValueError, match="must name the source attempt as parent"):
        store.record_replay(
            ReplayVerification(
                campaign_id=campaign.campaign_id,
                source_attempt_id=source.attempt_id,
                replay_attempt_ids=(replay.attempt_id,),
                required_successes=1,
                verifier="reviewer",
            )
        )


def test_replay_attempt_from_another_campaign_cannot_confirm(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    first = ledger.create_campaign(_campaign())
    second = ledger.create_campaign(
        Campaign(
            name="Other campaign",
            scope=_campaign().scope,
            objective="Separate boundary",
            success_criteria=_campaign().success_criteria,
        )
    )
    source = ledger.record_attempt(
        Attempt(
            campaign_id=first.campaign_id,
            attack_family="test",
            hypothesis="source",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.SUCCESSFUL,
        )
    )
    foreign_replay = ledger.record_attempt(
        Attempt(
            campaign_id=second.campaign_id,
            attack_family="test",
            hypothesis="foreign replay",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.SUCCESSFUL,
        )
    )

    with pytest.raises(ValueError, match="replay attempt belongs to a different campaign"):
        VerificationStore(path).record_replay(
            ReplayVerification(
                campaign_id=first.campaign_id,
                source_attempt_id=source.attempt_id,
                replay_attempt_ids=(foreign_replay.attempt_id,),
                required_successes=1,
                verifier="reviewer",
            )
        )
