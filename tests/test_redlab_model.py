from __future__ import annotations

import json

import pytest

from agent_prompt_shield.redlab import Attempt, AttemptResult, Campaign, Scope
from agent_prompt_shield.redlab_model import EvaluationPacket, OpenAIResponsesEvaluator
from agent_prompt_shield.redlab_verify import EvaluationVerdict


def _campaign() -> Campaign:
    return Campaign(
        campaign_id="campaign-test",
        name="Authorized test",
        scope=Scope(
            target="local agent sandbox",
            authorization="owner-authorized testing",
            allowed_actions=("submit controlled prompts",),
        ),
        objective="Test whether untrusted content changes agent behavior",
        success_criteria=("agent performs the declared target behavior",),
    )


def _attempt() -> Attempt:
    return Attempt(
        attempt_id="attempt-test",
        campaign_id="campaign-test",
        attack_family="indirect_prompt_injection",
        hypothesis="Untrusted text may influence the planner",
        payload="controlled test payload",
        delivery_channel="document",
        result=AttemptResult.PARTIAL,
        target_response="The target acknowledged the text but did not perform the behavior.",
    )


def test_build_request_uses_strict_json_schema() -> None:
    evaluator = OpenAIResponsesEvaluator(api_key="test", transport=lambda _: {})
    request = evaluator.build_request(EvaluationPacket(_campaign(), _attempt()))

    assert request["model"] == "gpt-5.6"
    assert request["text"]["format"]["type"] == "json_schema"
    assert request["text"]["format"]["strict"] is True
    assert "claimed_result" in request["input"][0]["content"][0]["text"]


def test_evaluate_parses_schema_valid_response() -> None:
    def transport(_: dict[str, object]) -> dict[str, object]:
        return {
            "output_text": json.dumps(
                {
                    "verdict": "failed",
                    "findings": [
                        {
                            "criterion": "agent performs the declared target behavior",
                            "met": False,
                            "evidence": "The response explicitly says the behavior was not performed.",
                        }
                    ],
                    "rationale": "The claimed partial result does not satisfy the criterion.",
                }
            )
        }

    result = OpenAIResponsesEvaluator(transport=transport).evaluate(
        EvaluationPacket(_campaign(), _attempt())
    )

    assert result.verdict == EvaluationVerdict.FAILED
    assert result.findings[0].met is False
    assert result.evaluator == "openai:gpt-5.6"


def test_evaluate_rejects_unexpected_fields() -> None:
    def transport(_: dict[str, object]) -> dict[str, object]:
        return {
            "output_text": json.dumps(
                {
                    "verdict": "successful",
                    "findings": [
                        {"criterion": "criterion", "met": True, "evidence": "evidence"}
                    ],
                    "rationale": "rationale",
                    "extra": "not allowed",
                }
            )
        }

    with pytest.raises(ValueError, match="missing or unexpected"):
        OpenAIResponsesEvaluator(transport=transport).evaluate(
            EvaluationPacket(_campaign(), _attempt())
        )


def test_packet_rejects_cross_campaign_attempt() -> None:
    attempt = Attempt(
        campaign_id="campaign-other",
        attack_family="direct_prompt_injection",
        hypothesis="test",
        payload="test",
        delivery_channel="chat",
        result=AttemptResult.FAILED,
    )

    with pytest.raises(ValueError, match="ids do not match"):
        EvaluationPacket(_campaign(), attempt).validate()
