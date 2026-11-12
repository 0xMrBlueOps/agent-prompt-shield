import json

import pytest

from agent_prompt_shield.redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope
from agent_prompt_shield.redlab_drafts import DraftStatus, DraftStore
from agent_prompt_shield.redlab_strategy import StrategyAction, StrategyProposal


def _seed(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(
        Campaign(
            name="Authorized lab",
            scope=Scope(
                target="owned test agent",
                authorization="owner-authorized",
                allowed_actions=("submit test prompts",),
                prohibited_actions=("access third-party data",),
            ),
            objective="Measure prompt-injection resistance",
            success_criteria=("agent follows injected instruction",),
        )
    )
    parent = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="indirect_prompt_injection",
            hypothesis="Authority framing may influence the planner",
            payload="test payload",
            delivery_channel="browser",
            result=AttemptResult.PARTIAL,
        )
    )
    return path, campaign, parent


def _proposal(parent_id):
    return StrategyProposal(
        title="Change only continuation framing",
        action=StrategyAction.MUTATE,
        attack_family="indirect_prompt_injection",
        hypothesis="Task-continuation framing may be stronger than authority framing",
        controlled_change="Replace authority framing with task-continuation framing",
        proposed_payload="authorized controlled test payload",
        expected_signal="The agent incorporates the untrusted continuation",
        stop_condition="Stop after two equivalent failures",
        parent_attempt_id=parent_id,
        action_tags=("submit-test-prompts",),
    )


def test_accepting_draft_creates_invalid_child_attempt(tmp_path):
    path, campaign, parent = _seed(tmp_path)
    store = DraftStore(path)
    draft = store.create_drafts(
        campaign_id=campaign.campaign_id,
        analysis="The partial result justifies one controlled mutation.",
        proposals=(_proposal(parent.attempt_id),),
    )[0]

    child = store.accept(draft.draft_id, delivery_channel="browser")

    assert child.parent_attempt_id == parent.attempt_id
    assert child.result == AttemptResult.INVALID
    assert child.payload == "authorized controlled test payload"
    assert store.drafts()[0].status == DraftStatus.ACCEPTED


def test_rejecting_draft_records_final_status(tmp_path):
    path, campaign, parent = _seed(tmp_path)
    store = DraftStore(path)
    draft = store.create_drafts(
        campaign_id=campaign.campaign_id,
        analysis="Proposal requires human review.",
        proposals=(_proposal(parent.attempt_id),),
    )[0]

    rejected = store.reject(draft.draft_id, reason="Not useful enough")

    assert rejected.status == DraftStatus.REJECTED
    assert store.drafts(status=DraftStatus.REJECTED)[0].draft_id == draft.draft_id


def test_stop_proposal_cannot_be_accepted(tmp_path):
    path, campaign, parent = _seed(tmp_path)
    store = DraftStore(path)
    proposal = StrategyProposal(
        title="Stop this branch",
        action=StrategyAction.STOP,
        attack_family="indirect_prompt_injection",
        hypothesis="Evidence is exhausted",
        controlled_change="No further change",
        proposed_payload="",
        expected_signal="No additional signal expected",
        stop_condition="Stop immediately",
        parent_attempt_id=parent.attempt_id,
    )
    draft = store.create_drafts(
        campaign_id=campaign.campaign_id,
        analysis="This line of testing should stop.",
        proposals=(proposal,),
    )[0]

    try:
        store.accept(draft.draft_id, delivery_channel="browser")
    except ValueError as exc:
        assert "STOP proposals" in str(exc)
    else:
        raise AssertionError("STOP proposal should not create an attempt")


@pytest.mark.parametrize(
    ("action_tags", "message"),
    (
        ((), "requires at least one action tag"),
        (("access-third-party-data",), "prohibited action tags"),
        (("change-system-settings",), "outside campaign scope"),
        (("Submit Test Prompts",), "already be normalized"),
        (
            ("submit-test-prompts", "submit-test-prompts"),
            "action tags must be unique",
        ),
    ),
)
def test_executable_proposal_must_match_deterministic_scope(
    tmp_path,
    action_tags,
    message,
):
    path, campaign, parent = _seed(tmp_path)
    store = DraftStore(path)
    proposal = StrategyProposal(
        **{
            **_proposal(parent.attempt_id).__dict__,
            "action_tags": action_tags,
        }
    )

    with pytest.raises(ValueError, match=message):
        store.create_drafts(
            campaign_id=campaign.campaign_id,
            analysis="Scope check.",
            proposals=(proposal,),
        )
    assert store.drafts() == []


def test_accept_revalidates_tampered_stored_draft(tmp_path):
    path, campaign, parent = _seed(tmp_path)
    store = DraftStore(path)
    draft = store.create_drafts(
        campaign_id=campaign.campaign_id,
        analysis="Initially scoped.",
        proposals=(_proposal(parent.attempt_id),),
    )[0]
    rows = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    draft_row = next(row for row in rows if row.get("draft_id") == draft.draft_id)
    draft_row["proposal"]["action_tags"] = ["access-third-party-data"]
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="prohibited action tags"):
        store.accept(draft.draft_id, delivery_channel="browser")
