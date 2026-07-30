from __future__ import annotations

from pathlib import Path

import pytest

from agent_prompt_shield.redlab import (
    Attempt,
    AttemptResult,
    Campaign,
    RedLabLedger,
    Scope,
)
from agent_prompt_shield.redlab_command import main
from agent_prompt_shield.redlab_report import build_campaign_report


def _campaign() -> Campaign:
    return Campaign(
        name="Authorized lab",
        scope=Scope(
            target="local test agent",
            authorization="owned system",
            allowed_actions=("submit controlled prompts",),
            prohibited_actions=("access third-party data",),
        ),
        objective="Measure instruction-boundary failures",
        success_criteria=("target performs the declared test action",),
    )


def test_complete_pending_attempt_without_duplicate(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(_campaign())
    pending = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="indirect_prompt_injection",
            hypothesis="untrusted content may influence planning",
            payload="controlled test payload",
            delivery_channel="manual_lab",
            result=AttemptResult.INVALID,
        )
    )

    completed = ledger.complete_attempt(
        pending.attempt_id,
        result=AttemptResult.PARTIAL,
        target_response="The target followed part of the test instruction.",
        failure_reason="Success criterion was only partly met.",
        lesson="The delivery channel was influential.",
    )

    attempts = ledger.attempts(campaign.campaign_id)
    assert len(attempts) == 1
    assert completed.attempt_id == pending.attempt_id
    assert attempts[0].result == AttemptResult.PARTIAL
    assert ledger.metrics(campaign.campaign_id)["partials"] == 1
    assert ledger.metrics(campaign.campaign_id)["pending"] == 0


def test_completed_attempt_cannot_be_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(_campaign())
    attempt = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="direct_prompt_injection",
            hypothesis="test",
            payload="payload",
            delivery_channel="local",
            result=AttemptResult.INVALID,
        )
    )
    ledger.complete_attempt(
        attempt.attempt_id,
        result=AttemptResult.FAILED,
        target_response="No effect.",
    )
    with pytest.raises(ValueError, match="already completed"):
        ledger.complete_attempt(
            attempt.attempt_id,
            result=AttemptResult.SUCCESSFUL,
            target_response="Replacement result.",
        )


def test_report_contains_scope_metrics_and_history(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(path)
    campaign = ledger.create_campaign(_campaign())
    attempt = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="tool_output_injection",
            hypothesis="tool output may influence the planner",
            payload="test marker",
            delivery_channel="local_tool",
            result=AttemptResult.FAILED,
            target_response="The planner ignored the marker.",
            failure_reason="Trust boundary held.",
            lesson="Keep provenance enforcement enabled.",
        )
    )

    report = build_campaign_report(path, campaign.campaign_id)
    assert "# Red Lab Campaign Report" in report.markdown
    assert "owned system" in report.markdown
    assert attempt.attempt_id in report.markdown
    assert "Attack success rate: 0.00%" in report.markdown
    assert "No independently evaluated" in report.markdown


def test_command_completes_attempt_and_writes_report(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(ledger_path)
    campaign = ledger.create_campaign(_campaign())
    attempt = ledger.record_attempt(
        Attempt(
            campaign_id=campaign.campaign_id,
            attack_family="memory_poisoning",
            hypothesis="controlled memory may persist",
            payload="lab-only marker",
            delivery_channel="local_memory",
            result=AttemptResult.INVALID,
        )
    )

    assert (
        main(
            [
                "--ledger",
                str(ledger_path),
                "complete-attempt",
                "--attempt",
                attempt.attempt_id,
                "--result",
                "failed",
                "--response",
                "Marker did not persist.",
            ]
        )
        == 0
    )
    output = tmp_path / "report.md"
    assert (
        main(
            [
                "--ledger",
                str(ledger_path),
                "report",
                "--campaign",
                campaign.campaign_id,
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert output.exists()
    assert "Marker did not persist." in output.read_text(encoding="utf-8")
