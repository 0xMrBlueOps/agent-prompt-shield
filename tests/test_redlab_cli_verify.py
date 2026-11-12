from __future__ import annotations

import json
from pathlib import Path

from agent_prompt_shield.redlab_cli import main


def test_cli_evaluation_and_replay_confirmation(tmp_path: Path, capsys) -> None:
    ledger = tmp_path / "ledger.jsonl"

    assert main([
        "--ledger", str(ledger),
        "init",
        "--name", "Authorized challenge",
        "--target", "local test agent",
        "--authorization", "owner-controlled environment",
        "--objective", "test instruction-boundary handling",
        "--allowed", "submit controlled prompts",
        "--success", "target performs the declared test action",
    ]) == 0
    campaign = json.loads(capsys.readouterr().out)

    assert main([
        "--ledger", str(ledger),
        "record",
        "--campaign", campaign["campaign_id"],
        "--family", "direct_prompt_injection",
        "--hypothesis", "target may follow lower-trust instructions",
        "--payload", "controlled test payload",
        "--channel", "chat",
        "--result", "successful",
        "--response", "declared test action completed",
    ]) == 0
    source = json.loads(capsys.readouterr().out)

    assert main([
        "--ledger", str(ledger),
        "evaluate",
        "--campaign", campaign["campaign_id"],
        "--attempt", source["attempt_id"],
        "--evaluator", "independent-reviewer",
        "--verdict", "successful",
        "--finding", "true|target performs the declared test action|transcript shows completion",
        "--rationale", "The evidence satisfies the campaign criterion.",
    ]) == 0
    capsys.readouterr()

    replay_ids: list[str] = []
    for result in ("successful", "failed"):
        assert main([
            "--ledger", str(ledger),
            "record",
            "--campaign", campaign["campaign_id"],
            "--family", "direct_prompt_injection",
            "--hypothesis", "fresh replay",
            "--payload", "controlled replay payload",
            "--channel", "chat",
            "--result", result,
            "--parent", source["attempt_id"],
        ]) == 0
        replay_ids.append(json.loads(capsys.readouterr().out)["attempt_id"])

    assert main([
        "--ledger", str(ledger),
        "verify-replay",
        "--campaign", campaign["campaign_id"],
        "--source", source["attempt_id"],
        "--replay", replay_ids[0],
        "--replay", replay_ids[1],
        "--required-successes", "1",
        "--verifier", "replay-verifier",
    ]) == 0
    replay_result = json.loads(capsys.readouterr().out)
    assert replay_result["passed"] is True
    assert replay_result["successes"] == 1

    assert main([
        "--ledger", str(ledger),
        "status",
        "--attempt", source["attempt_id"],
    ]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["confirmed_success"] is True
    assert len(status["evaluations"]) == 1
    assert len(status["replay_verifications"]) == 1
