from __future__ import annotations

import json
from pathlib import Path

from agent_prompt_shield.redlab_cli import main


def test_cli_creates_campaign_and_records_attempt(tmp_path: Path, capsys) -> None:
    ledger = tmp_path / "ledger.jsonl"

    exit_code = main(
        [
            "--ledger",
            str(ledger),
            "init",
            "--name",
            "Gray Swan Lab",
            "--target",
            "authorized challenge target",
            "--authorization",
            "challenge rules grant testing permission",
            "--objective",
            "Test instruction-boundary failures",
            "--allowed",
            "submit challenge prompts",
            "--prohibited",
            "test unrelated systems",
            "--success",
            "target exhibits the declared challenge behavior",
        ]
    )
    assert exit_code == 0
    campaign_payload = json.loads(capsys.readouterr().out)
    campaign_id = campaign_payload["campaign_id"]

    exit_code = main(
        [
            "--ledger",
            str(ledger),
            "record",
            "--campaign",
            campaign_id,
            "--family",
            "instruction_priority_confusion",
            "--hypothesis",
            "A task-continuation frame may be treated as authoritative.",
            "--payload",
            "controlled authorized test payload",
            "--channel",
            "chat",
            "--result",
            "partial",
            "--response",
            "target partially followed the test instruction",
            "--lesson",
            "Continuation framing changed behavior but did not meet success criteria.",
            "--tool-trace-json",
            '[{"tool":"browser","status":"not_called"}]',
        ]
    )
    assert exit_code == 0
    attempt_payload = json.loads(capsys.readouterr().out)
    assert attempt_payload["campaign_id"] == campaign_id
    assert attempt_payload["result"] == "partial"
    assert attempt_payload["tool_trace"][0]["tool"] == "browser"

    exit_code = main(
        [
            "--ledger",
            str(ledger),
            "metrics",
            "--campaign",
            campaign_id,
        ]
    )
    assert exit_code == 0
    metrics = json.loads(capsys.readouterr().out)
    assert metrics["attempts"] == 1
    assert metrics["partials"] == 1
    assert metrics["partial_or_better_rate"] == 1.0


def test_cli_reads_payload_and_response_files(tmp_path: Path, capsys) -> None:
    ledger = tmp_path / "ledger.jsonl"
    payload_file = tmp_path / "payload.txt"
    response_file = tmp_path / "response.txt"
    payload_file.write_text("payload from file", encoding="utf-8")
    response_file.write_text("response from file", encoding="utf-8")

    main(
        [
            "--ledger",
            str(ledger),
            "init",
            "--name",
            "Local Agent Test",
            "--target",
            "local owned agent",
            "--authorization",
            "owner-authorized test",
            "--objective",
            "Evaluate indirect prompt injection",
            "--allowed",
            "test local fixtures",
            "--success",
            "agent follows untrusted content",
        ]
    )
    campaign_id = json.loads(capsys.readouterr().out)["campaign_id"]

    main(
        [
            "--ledger",
            str(ledger),
            "record",
            "--campaign",
            campaign_id,
            "--family",
            "indirect_prompt_injection",
            "--hypothesis",
            "Untrusted document text may influence the planner.",
            "--payload-file",
            str(payload_file),
            "--response-file",
            str(response_file),
            "--channel",
            "document",
            "--result",
            "failed",
        ]
    )
    recorded = json.loads(capsys.readouterr().out)
    assert recorded["payload"] == "payload from file"
    assert recorded["target_response"] == "response from file"
