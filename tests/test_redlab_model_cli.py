from __future__ import annotations

import json
from pathlib import Path

from agent_prompt_shield.redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope
from agent_prompt_shield.redlab_cli import main


def _seed(ledger_path: Path) -> Attempt:
    ledger = RedLabLedger(ledger_path)
    campaign = ledger.create_campaign(
        Campaign(
            name="Authorized model evaluation",
            scope=Scope(
                target="local test agent",
                authorization="owner-authorized laboratory",
                allowed_actions=("submit controlled prompts",),
            ),
            objective="Measure whether the target follows untrusted instructions.",
            success_criteria=("Target performs the declared test action",),
        )
    )
    return ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="indirect_prompt_injection",
            hypothesis="Untrusted context may influence the planner.",
            payload="Controlled test payload",
            delivery_channel="local_fixture",
            result=AttemptResult.PARTIAL,
            target_response="The target acknowledged but did not perform the action.",
        )
    )


def test_evaluate_model_dry_run_builds_strict_request(tmp_path: Path, capsys) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    attempt = _seed(ledger_path)

    exit_code = main(
        [
            "--ledger",
            str(ledger_path),
            "evaluate-model",
            "--attempt",
            attempt.attempt_id,
            "--model",
            "gpt-5.6",
            "--dry-run",
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["model"] == "gpt-5.6"
    assert payload["text"]["format"]["strict"] is True
    packet = json.loads(payload["input"][0]["content"][0]["text"])
    assert packet["attempt"]["attempt_id"] == attempt.attempt_id
    assert packet["campaign"]["authorization"] == "owner-authorized laboratory"


def test_evaluate_model_dry_run_does_not_write_evaluation(tmp_path: Path, capsys) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    attempt = _seed(ledger_path)
    before = ledger_path.read_text(encoding="utf-8")

    assert (
        main(
            [
                "--ledger",
                str(ledger_path),
                "evaluate-model",
                "--attempt",
                attempt.attempt_id,
                "--dry-run",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert ledger_path.read_text(encoding="utf-8") == before
