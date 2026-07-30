from __future__ import annotations

import json

import pytest

from agent_prompt_shield.redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope
from agent_prompt_shield.redlab_cli import main
from agent_prompt_shield.redlab_drafts import DraftStore
from agent_prompt_shield.redlab_strategy import StrategyAction, StrategyProposal


def _seed_campaign(path):
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(
        Campaign(
            name="Authorized challenge",
            scope=Scope(
                target="local challenge target",
                authorization="owner-authorized lab",
                allowed_actions=("submit test prompts",),
                prohibited_actions=("access third-party data",),
            ),
            objective="Test instruction-boundary handling",
            success_criteria=("target performs the declared challenge behavior",),
        )
    )
    attempt = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="indirect_prompt_injection",
            hypothesis="untrusted context may influence planning",
            payload="controlled test payload",
            delivery_channel="local_lab",
            result=AttemptResult.PARTIAL,
            target_response="The target acknowledged the instruction but did not act.",
            lesson="Task framing influenced the response.",
        )
    )
    return campaign, attempt


def test_strategy_dry_run_builds_request_without_drafts(tmp_path, capsys):
    ledger_path = tmp_path / "ledger.jsonl"
    campaign, attempt = _seed_campaign(ledger_path)

    result = main(
        [
            "--ledger",
            str(ledger_path),
            "strategy",
            "--attempt",
            attempt.attempt_id,
            "--max-proposals",
            "2",
            "--dry-run",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["model"] == "gpt-5.6"
    packet = json.loads(payload["input"][0]["content"][0]["text"])
    assert packet["campaign"]["campaign_id"] == campaign.campaign_id
    assert packet["focus_attempt_id"] == attempt.attempt_id
    assert packet["max_proposals"] == 2
    assert payload["max_output_tokens"] == 6_000
    assert DraftStore(ledger_path).drafts() == []


def test_drafts_accept_and_reject_commands(tmp_path, capsys):
    ledger_path = tmp_path / "ledger.jsonl"
    campaign, attempt = _seed_campaign(ledger_path)
    store = DraftStore(ledger_path)
    proposals = (
        StrategyProposal(
            title="Single-variable mutation",
            action=StrategyAction.MUTATE,
            attack_family="indirect_prompt_injection",
            hypothesis="changing placement may alter instruction priority",
            controlled_change="move the same instruction to the end of the document",
            proposed_payload="same controlled payload at document end",
            expected_signal="target references the final instruction",
            stop_condition="stop after two identical failures",
            parent_attempt_id=attempt.attempt_id,
            action_tags=("submit-test-prompts",),
        ),
        StrategyProposal(
            title="No useful scoped test remains",
            action=StrategyAction.STOP,
            attack_family="indirect_prompt_injection",
            hypothesis="current evidence is exhausted",
            controlled_change="none",
            proposed_payload="",
            expected_signal="no further experiment",
            stop_condition="campaign owner expands evidence or scope",
            parent_attempt_id=attempt.attempt_id,
        ),
    )
    drafts = store.create_drafts(
        campaign_id=campaign.campaign_id,
        analysis="One controlled mutation remains useful.",
        proposals=proposals,
    )

    list_result = main(["--ledger", str(ledger_path), "drafts", "--json"])
    assert list_result == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == 2
    assert all(item["status"] == "pending" for item in listed)

    accept_result = main(
        [
            "--ledger",
            str(ledger_path),
            "accept-draft",
            "--draft",
            drafts[0].draft_id,
            "--channel",
            "manual_challenge",
        ]
    )
    assert accept_result == 0
    accepted = json.loads(capsys.readouterr().out)
    assert accepted["result"] == "invalid"
    assert accepted["parent_attempt_id"] == attempt.attempt_id

    reject_result = main(
        [
            "--ledger",
            str(ledger_path),
            "reject-draft",
            "--draft",
            drafts[1].draft_id,
            "--reason",
            "Campaign owner wants another evidence review first.",
        ]
    )
    assert reject_result == 0
    rejected = json.loads(capsys.readouterr().out)
    assert rejected["status"] == "rejected"

    statuses = {item.draft_id: item.status.value for item in store.drafts()}
    assert statuses[drafts[0].draft_id] == "accepted"
    assert statuses[drafts[1].draft_id] == "rejected"


def test_cli_help_lists_all_supported_workflows(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    output = capsys.readouterr().out
    for command in (
        "init",
        "record",
        "complete-attempt",
        "strategy",
        "strategy-tournament",
        "drafts",
        "accept-draft",
        "reject-draft",
        "evaluate-model",
        "verify-replay",
        "status",
        "metrics",
        "report",
    ):
        assert command in output
