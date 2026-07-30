from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .redlab import Attempt, AttemptResult, RedLabLedger
from .redlab_cli import main as legacy_main
from .redlab_report import build_campaign_report


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    command_index = _command_index(args)
    if command_index is None:
        return legacy_main(args)
    command = args[command_index]
    if command not in {"complete-attempt", "report"}:
        return legacy_main(args)

    ledger_path = _ledger_path(args)
    command_args = args[command_index + 1 :]
    if command == "complete-attempt":
        return _complete_attempt(ledger_path, command_args)
    return _report(ledger_path, command_args)


def _complete_attempt(ledger_path: str, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="agent-redlab complete-attempt")
    parser.add_argument("--attempt", required=True)
    parser.add_argument(
        "--result",
        required=True,
        choices=[
            AttemptResult.FAILED.value,
            AttemptResult.PARTIAL.value,
            AttemptResult.SUCCESSFUL.value,
        ],
    )
    parser.add_argument("--response")
    parser.add_argument("--response-file", type=Path)
    parser.add_argument("--tool-trace-json", default="[]")
    parser.add_argument("--failure-reason", default="")
    parser.add_argument("--lesson", default="")
    parsed = parser.parse_args(argv)
    response = _read_text(parsed.response, parsed.response_file, parser)
    try:
        trace = json.loads(parsed.tool_trace_json)
    except json.JSONDecodeError as exc:
        parser.error(f"--tool-trace-json must be valid JSON: {exc}")
    if not isinstance(trace, list) or not all(isinstance(item, dict) for item in trace):
        parser.error("--tool-trace-json must decode to an array of objects")
    try:
        item = RedLabLedger(ledger_path).complete_attempt(
            parsed.attempt,
            result=AttemptResult(parsed.result),
            target_response=response,
            tool_trace=tuple(trace),
            failure_reason=parsed.failure_reason,
            lesson=parsed.lesson,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(_attempt_to_dict(item), indent=2))
    return 0


def _report(ledger_path: str, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="agent-redlab report")
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--output", type=Path)
    parsed = parser.parse_args(argv)
    try:
        report = build_campaign_report(ledger_path, parsed.campaign)
    except ValueError as exc:
        parser.error(str(exc))
    if parsed.output is None:
        print(report.markdown)
    else:
        path = report.write(parsed.output)
        print(json.dumps({"campaign_id": parsed.campaign, "output": str(path)}, indent=2))
    return 0


def _command_index(args: list[str]) -> int | None:
    index = 0
    while index < len(args):
        value = args[index]
        if value == "--ledger":
            index += 2
            continue
        if value.startswith("--ledger="):
            index += 1
            continue
        if value.startswith("-"):
            index += 1
            continue
        return index
    return None


def _ledger_path(args: list[str]) -> str:
    for index, value in enumerate(args):
        if value == "--ledger" and index + 1 < len(args):
            return args[index + 1]
        if value.startswith("--ledger="):
            return value.split("=", 1)[1]
    return ".redlab/ledger.jsonl"


def _read_text(inline: str | None, file_path: Path | None, parser: argparse.ArgumentParser) -> str:
    if inline is not None and file_path is not None:
        parser.error("Use either --response or --response-file, not both")
    if file_path is not None:
        try:
            return file_path.read_text(encoding="utf-8")
        except OSError as exc:
            parser.error(f"Could not read response file: {exc}")
    if inline is not None:
        return inline
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _attempt_to_dict(item: Attempt) -> dict[str, object]:
    return {
        "attempt_id": item.attempt_id,
        "campaign_id": item.campaign_id,
        "attack_family": item.attack_family,
        "hypothesis": item.hypothesis,
        "payload": item.payload,
        "delivery_channel": item.delivery_channel,
        "result": item.result.value,
        "target_response": item.target_response,
        "tool_trace": list(item.tool_trace),
        "failure_reason": item.failure_reason,
        "lesson": item.lesson,
        "parent_attempt_id": item.parent_attempt_id,
        "created_at": item.created_at,
    }


if __name__ == "__main__":
    raise SystemExit(main())
