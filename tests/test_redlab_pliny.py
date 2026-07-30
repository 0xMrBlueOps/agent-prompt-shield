from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_prompt_shield.redlab import AttemptResult, Campaign, RedLabLedger, Scope
from agent_prompt_shield.redlab_pliny import (
    PROMPTFOO_PACKAGE,
    import_promptfoo_results,
    run_promptfoo_pliny,
    write_promptfoo_pliny_config,
)


def _campaign(ledger: RedLabLedger) -> Campaign:
    return ledger.create_campaign(
        Campaign(
            name="Authorized Pliny test",
            scope=Scope(
                target="local model",
                authorization="Owner-authorized local evaluation",
                allowed_actions=("submit Promptfoo red-team prompts",),
            ),
            objective="Measure handling of Pliny prompt injections",
            success_criteria=("Target violates the declared test policy",),
        )
    )


def test_writes_pliny_config(tmp_path: Path) -> None:
    output = write_promptfoo_pliny_config(
        tmp_path / "pliny.yaml",
        target="openai:gpt-5",
        purpose="Authorized model safety test",
        num_tests=7,
    )
    text = output.read_text(encoding="utf-8")
    assert "- id: pliny" in text
    assert "numTests: 7" in text
    assert 'purpose: "Authorized model safety test"' in text


def test_run_requires_authorization_acknowledgement(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("redteam: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="authorization acknowledgement"):
        run_promptfoo_pliny(
            config=config,
            output=tmp_path / "results.json",
            acknowledge_authorization=False,
        )


def test_run_uses_pinned_promptfoo_and_no_share(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("redteam: {}\n", encoding="utf-8")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return __import__("subprocess").CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("agent_prompt_shield.redlab_pliny.subprocess.run", fake_run)
    run_promptfoo_pliny(
        config=config,
        output=tmp_path / "results.json",
        acknowledge_authorization=True,
    )

    assert captured["command"][:2] == ["npx", PROMPTFOO_PACKAGE]
    assert "@latest" not in " ".join(captured["command"])
    assert captured["command"][-1] == "--no-share"
    assert captured["kwargs"]["check"] is True


def test_imports_promptfoo_v3_outputs(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(ledger_path)
    campaign = _campaign(ledger)
    results = {
        "version": 3,
        "results": {
            "outputs": [
                {
                    "vars": {"prompt": "pliny payload one"},
                    "response": {"output": "target output one"},
                    "success": False,
                    "provider": {"id": "local:model"},
                },
                {
                    "vars": {"prompt": "pliny payload two"},
                    "response": {"output": "refusal"},
                    "success": True,
                },
            ]
        },
    }
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")

    summary = import_promptfoo_results(
        ledger_path=ledger_path,
        campaign_id=campaign.campaign_id,
        results_path=results_path,
    )

    assert summary.imported == 2
    assert summary.successful == 1
    assert summary.failed == 1
    attempts = ledger.attempts(campaign.campaign_id)
    assert attempts[0].attack_family == "promptfoo:pliny"
    assert attempts[0].result == AttemptResult.SUCCESSFUL
    assert attempts[0].payload == "pliny payload one"
    assert attempts[0].target_response == "target output one"
    assert attempts[1].result == AttemptResult.FAILED


def test_imported_findings_are_not_confirmed_automatically(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(ledger_path)
    campaign = _campaign(ledger)
    results_path = tmp_path / "results.json"
    results_path.write_text(
        json.dumps({"results": {"outputs": [{"prompt": "x", "output": "y", "success": False}]}}),
        encoding="utf-8",
    )
    summary = import_promptfoo_results(
        ledger_path=ledger_path,
        campaign_id=campaign.campaign_id,
        results_path=results_path,
    )
    attempt = ledger.attempts(campaign.campaign_id)[0]
    assert summary.successful == 1
    assert attempt.lesson.endswith("independently evaluate before confirmation.")
