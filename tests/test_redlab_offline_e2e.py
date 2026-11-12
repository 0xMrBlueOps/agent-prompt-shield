from pathlib import Path

from agent_prompt_shield.redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope
from agent_prompt_shield.redlab_drafts import DraftStore
from agent_prompt_shield.redlab_report import build_campaign_report
from agent_prompt_shield.redlab_strategy import StrategyAction, StrategyProposal
from agent_prompt_shield.redlab_verify import (
    CriterionFinding,
    EvaluationVerdict,
    IndependentEvaluation,
    ReplayVerification,
    VerificationStore,
)


def test_offline_campaign_to_confirmed_report(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(
        Campaign(
            name="Offline authorized lab",
            scope=Scope(
                target="local fixture",
                authorization="test-owned fixture",
                allowed_actions=("submit controlled prompts",),
                prohibited_actions=("access external systems",),
            ),
            objective="Verify the complete evidence workflow",
            success_criteria=("fixture emits the declared marker",),
        )
    )
    baseline = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="instruction_boundary",
            hypothesis="baseline framing may emit the marker",
            payload="baseline fixture input",
            delivery_channel="offline_fixture",
            result=AttemptResult.FAILED,
            target_response="No marker.",
        )
    )
    drafts = DraftStore(path)
    draft = drafts.create_drafts(
        campaign_id=campaign.campaign_id,
        analysis="A fresh-session framing change is still in scope.",
        proposals=(
            StrategyProposal(
                title="Fresh-session retry",
                action=StrategyAction.MUTATE,
                attack_family="instruction_boundary",
                hypothesis="fresh-session framing may emit the marker",
                controlled_change="change only the session state",
                proposed_payload="controlled fixture input",
                expected_signal="fixture emits the declared marker",
                stop_condition="stop after one replay",
                parent_attempt_id=baseline.attempt_id,
                action_tags=("submit-controlled-prompts",),
            ),
        ),
    )[0]
    source = drafts.accept(draft.draft_id, delivery_channel="offline_fixture")
    source = ledger.complete_attempt(
        source.attempt_id,
        result=AttemptResult.SUCCESSFUL,
        target_response="Declared marker emitted.",
    )
    verification = VerificationStore(path)
    verification.record_evaluation(
        IndependentEvaluation(
            campaign_id=campaign.campaign_id,
            attempt_id=source.attempt_id,
            evaluator="offline-independent-fixture",
            verdict=EvaluationVerdict.SUCCESSFUL,
            findings=(
                CriterionFinding(
                    campaign.success_criteria[0],
                    True,
                    "The fixture transcript contains the declared marker.",
                ),
            ),
            rationale="The exact campaign criterion is satisfied.",
        )
    )
    replay = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family=source.attack_family,
            hypothesis="fresh-session replay",
            payload=source.payload,
            delivery_channel="offline_fixture",
            result=AttemptResult.SUCCESSFUL,
            target_response="Declared marker emitted.",
            parent_attempt_id=source.attempt_id,
        )
    )
    verification.record_replay(
        ReplayVerification(
            campaign_id=campaign.campaign_id,
            source_attempt_id=source.attempt_id,
            replay_attempt_ids=(replay.attempt_id,),
            required_successes=1,
            verifier="offline-replay-fixture",
        )
    )

    assert verification.confirmed_success(source.attempt_id)
    report = build_campaign_report(path, campaign.campaign_id).markdown
    assert f"### Attempt: {source.attempt_id}" in report
    assert "successful (confirmed)" in report
    assert "Confirmed reproducible successes: 1" in report
