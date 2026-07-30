from pathlib import Path

import pytest

from agent_prompt_shield.redlab import (
    Attempt,
    AttemptResult,
    Campaign,
    RedLabLedger,
    Scope,
)


def build_campaign() -> Campaign:
    return Campaign(
        name="Authorized Gray Swan exercise",
        scope=Scope(
            target="grayswan-demo-target",
            authorization="User-owned challenge account and published competition scope",
            allowed_actions=("submit prompts", "analyze transcripts"),
            prohibited_actions=("target unrelated production systems",),
        ),
        objective="Test resistance to indirect prompt injection.",
        success_criteria=("Target performs the declared challenge behavior",),
    )


def test_campaign_and_attempt_round_trip(tmp_path: Path) -> None:
    ledger = RedLabLedger(tmp_path / "campaign.jsonl")
    campaign = ledger.create_campaign(build_campaign())

    attempt = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="indirect_prompt_injection",
            hypothesis="A tool result may be treated as higher-authority instructions.",
            payload="Controlled authorized test payload",
            delivery_channel="tool_output",
            result=AttemptResult.PARTIAL,
            target_response="The target acknowledged part of the injected objective.",
            lesson="Task-continuation framing influenced the target more than role claims.",
        )
    )

    assert ledger.campaigns() == [campaign]
    assert ledger.attempts(campaign.campaign_id) == [attempt]
    assert ledger.metrics(campaign.campaign_id) == {
        "attempts": 1,
        "successes": 0,
        "partials": 1,
        "failures": 0,
        "attack_success_rate": 0.0,
        "partial_or_better_rate": 1.0,
    }


def test_unknown_campaign_is_rejected(tmp_path: Path) -> None:
    ledger = RedLabLedger(tmp_path / "campaign.jsonl")

    with pytest.raises(ValueError, match="unknown campaign_id"):
        ledger.record_attempt(
            Attempt(
                campaign_id="campaign-missing",
                attack_family="direct_prompt_injection",
                hypothesis="test",
                payload="test",
                delivery_channel="chat",
                result=AttemptResult.FAILED,
            )
        )


def test_parent_attempt_builds_tree(tmp_path: Path) -> None:
    ledger = RedLabLedger(tmp_path / "campaign.jsonl")
    campaign = ledger.create_campaign(build_campaign())
    parent = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="goal_hijacking",
            hypothesis="Initial framing test",
            payload="parent",
            delivery_channel="chat",
            result=AttemptResult.FAILED,
        )
    )
    child = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="goal_hijacking",
            hypothesis="Mutate only the authority framing",
            payload="child",
            delivery_channel="chat",
            result=AttemptResult.SUCCESSFUL,
            parent_attempt_id=parent.attempt_id,
        )
    )

    tree = ledger.attempt_tree(campaign.campaign_id)
    assert tree[None] == [parent]
    assert tree[parent.attempt_id] == [child]
