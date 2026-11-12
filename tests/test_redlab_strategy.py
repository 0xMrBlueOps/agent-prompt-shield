from agent_prompt_shield.redlab import Attempt, AttemptResult, Campaign, Scope
from agent_prompt_shield.redlab_strategy import (
    OpenAIResponsesStrategist,
    StrategyAction,
    StrategyPacket,
    select_strategy_context,
)


def make_campaign() -> Campaign:
    return Campaign(
        campaign_id="campaign-1",
        name="Authorized lab",
        scope=Scope(
            target="local test agent",
            authorization="owner-authorized lab",
            allowed_actions=("submit prompts",),
            prohibited_actions=("access external systems",),
        ),
        objective="Test instruction-boundary behavior",
        success_criteria=("target performs the declared lab action",),
    )


def make_attempt(
    attempt_id: str,
    result: AttemptResult,
    *,
    parent: str | None = None,
) -> Attempt:
    return Attempt(
        attempt_id=attempt_id,
        campaign_id="campaign-1",
        attack_family="instruction_confusion",
        hypothesis=f"hypothesis {attempt_id}",
        payload=f"payload {attempt_id}",
        delivery_channel="manual",
        result=result,
        target_response=f"response {attempt_id}",
        parent_attempt_id=parent,
    )


def test_strategist_parses_controlled_proposal() -> None:
    attempts = (
        make_attempt("attempt-root", AttemptResult.FAILED),
        make_attempt("attempt-child", AttemptResult.PARTIAL, parent="attempt-root"),
    )

    def transport(request):
        assert request["text"]["format"]["strict"] is True
        return {
            "output_text": (
                '{"analysis":"The partial result suggests the framing mattered.",'
                '"proposals":[{"title":"Change placement only","action":"mutate",'
                '"attack_family":"instruction_confusion",'
                '"hypothesis":"Moving the same instruction later may change priority.",'
                '"controlled_change":"Change only instruction placement.",'
                '"proposed_payload":"same content, moved later",'
                '"expected_signal":"More direct task deviation",'
                '"stop_condition":"Stop after two identical failures",'
                '"action_tags":["submit-prompts"],'
                '"parent_attempt_id":"attempt-child"}]}'
            )
        }

    strategist = OpenAIResponsesStrategist(model="test-model", transport=transport)
    analysis, proposals = strategist.propose(
        StrategyPacket(
            campaign=make_campaign(),
            attempts=attempts,
            focus_attempt_id="attempt-child",
            max_proposals=2,
        )
    )

    assert "partial result" in analysis
    assert len(proposals) == 1
    assert proposals[0].action == StrategyAction.MUTATE
    assert proposals[0].action_tags == ("submit-prompts",)
    assert proposals[0].parent_attempt_id == "attempt-child"


def test_strategist_rejects_unknown_parent() -> None:
    attempts = (make_attempt("attempt-root", AttemptResult.FAILED),)

    def transport(_request):
        return {
            "output_text": (
                '{"analysis":"test","proposals":[{"title":"x","action":"retry",'
                '"attack_family":"instruction_confusion","hypothesis":"x",'
                '"controlled_change":"x","proposed_payload":"x",'
                '"expected_signal":"x","stop_condition":"x",'
                '"action_tags":["submit-prompts"],'
                '"parent_attempt_id":"missing"}]}'
            )
        }

    strategist = OpenAIResponsesStrategist(model="test-model", transport=transport)
    try:
        strategist.propose(
            StrategyPacket(
                campaign=make_campaign(),
                attempts=attempts,
                focus_attempt_id="attempt-root",
            )
        )
    except ValueError as exc:
        assert "unknown parent" in str(exc)
    else:
        raise AssertionError("expected unknown-parent validation failure")


def test_strategist_rejects_malformed_proposal_locally() -> None:
    attempts = (make_attempt("attempt-root", AttemptResult.FAILED),)

    def transport(_request):
        return {
            "output_text": (
                '{"analysis":"test","proposals":[{"title":"x","action":"retry",'
                '"attack_family":"instruction_confusion","hypothesis":"x",'
                '"controlled_change":"x","proposed_payload":"x",'
                '"expected_signal":"x","stop_condition":"x",'
                '"action_tags":"submit-prompts",'
                '"parent_attempt_id":"attempt-root"}]}'
            )
        }

    strategist = OpenAIResponsesStrategist(model="test-model", transport=transport)

    try:
        strategist.propose(
            StrategyPacket(
                campaign=make_campaign(),
                attempts=attempts,
                focus_attempt_id="attempt-root",
            )
        )
    except ValueError as exc:
        assert "action_tags must be an array" in str(exc)
    else:
        raise AssertionError("expected malformed-proposal validation failure")


def test_select_strategy_context_keeps_lineage_and_failed_sibling() -> None:
    attempts = [
        make_attempt("root", AttemptResult.FAILED),
        make_attempt("child-a", AttemptResult.PARTIAL, parent="root"),
        make_attempt("child-b", AttemptResult.FAILED, parent="root"),
        make_attempt("grandchild", AttemptResult.PARTIAL, parent="child-a"),
    ]
    selected = select_strategy_context(attempts, "grandchild")
    ids = {item.attempt_id for item in selected}
    assert {"root", "child-a", "grandchild"}.issubset(ids)
