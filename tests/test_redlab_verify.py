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
