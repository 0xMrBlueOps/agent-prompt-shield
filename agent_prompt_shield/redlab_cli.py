from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-redlab",
        description="Evidence-driven CLI for authorized AI red-team campaigns.",
    )
    parser.add_argument(
        "--ledger",
        default=".redlab/ledger.jsonl",
        help="Append-only JSONL ledger path.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create an authorized campaign.")
    init.add_argument("--name", required=True)
    init.add_argument("--target", required=True)
    init.add_argument("--authorization", required=True)
    init.add_argument("--objective", required=True)
    init.add_argument("--allowed", action="append", required=True)
    init.add_argument("--prohibited", action="append", default=[])
    init.add_argument("--disclosure", action="append", default=[])
    init.add_argument("--success", action="append", required=True)

    record = subparsers.add_parser("record", help="Record an experiment and target transcript.")
    record.add_argument("--campaign", required=True)
    record.add_argument("--family", required=True)
    record.add_argument("--hypothesis", required=True)
    record.add_argument("--payload", help="Exact test payload. Defaults to stdin when omitted.")
    record.add_argument("--payload-file", type=Path)
    record.add_argument("--channel", required=True)
    record.add_argument("--result", required=True, choices=[item.value for item in AttemptResult])
    record.add_argument("--response", help="Target response/transcript text.")
    record.add_argument("--response-file", type=Path)
    record.add_argument("--failure-reason", default="")
    record.add_argument("--lesson", default="")
    record.add_argument("--parent")
    record.add_argument(
        "--tool-trace-json",
        default="[]",
        help="JSON array containing the target's observed tool trace.",
    )

    campaigns = subparsers.add_parser("campaigns", help="List campaigns.")
    campaigns.add_argument("--json", action="store_true")

    attempts = subparsers.add_parser("attempts", help="List attempts for a campaign.")
    attempts.add_argument("--campaign", required=True)
    attempts.add_argument("--json", action="store_true")

    metrics = subparsers.add_parser("metrics", help="Show campaign metrics.")
    metrics.add_argument("--campaign", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ledger = RedLabLedger(args.ledger)

    if args.command == "init":
        campaign = ledger.create_campaign(
            Campaign(
                name=args.name,
                scope=Scope(
                    target=args.target,
                    authorization=args.authorization,
                    allowed_actions=tuple(args.allowed),
                    prohibited_actions=tuple(args.prohibited),
                    disclosure_requirements=tuple(args.disclosure),
                ),
                objective=args.objective,
                success_criteria=tuple(args.success),
            )
        )
        print(json.dumps(_campaign_to_dict(campaign), indent=2))
        return 0

    if args.command == "record":
        payload = _read_text_argument(
            inline=args.payload,
            file_path=args.payload_file,
            stdin_fallback=True,
            parser=parser,
            label="payload",
        )
        response = _read_text_argument(
            inline=args.response,
            file_path=args.response_file,
            stdin_fallback=False,
            parser=parser,
            label="response",
        )
        try:
            raw_trace = json.loads(args.tool_trace_json)
        except json.JSONDecodeError as exc:
            parser.error(f"--tool-trace-json must be valid JSON: {exc}")
        if not isinstance(raw_trace, list) or not all(isinstance(item, dict) for item in raw_trace):
            parser.error("--tool-trace-json must decode to an array of objects.")

        attempt = ledger.record_attempt(
            Attempt(
                campaign_id=args.campaign,
                attack_family=args.family,
                hypothesis=args.hypothesis,
                payload=payload,
                delivery_channel=args.channel,
                result=AttemptResult(args.result),
                target_response=response,
                tool_trace=tuple(raw_trace),
                failure_reason=args.failure_reason,
                lesson=args.lesson,
                parent_attempt_id=args.parent,
            )
        )
        print(json.dumps(_attempt_to_dict(attempt), indent=2))
        return 0

    if args.command == "campaigns":
        items = ledger.campaigns()
        if args.json:
            print(json.dumps([_campaign_to_dict(item) for item in items], indent=2))
        else:
            for item in items:
                print(f"{item.campaign_id}\t{item.name}\t{item.scope.target}")
        return 0

    if args.command == "attempts":
        items = ledger.attempts(args.campaign)
        if args.json:
            print(json.dumps([_attempt_to_dict(item) for item in items], indent=2))
        else:
            for item in items:
                parent = item.parent_attempt_id or "root"
                print(f"{item.attempt_id}\t{item.result.value}\t{item.attack_family}\tparent={parent}")
        return 0

    if args.command == "metrics":
        print(json.dumps(ledger.metrics(args.campaign), indent=2))
        return 0

    parser.error(f"Unknown command: {args.command}")


def _read_text_argument(
    *,
    inline: str | None,
    file_path: Path | None,
    stdin_fallback: bool,
    parser: argparse.ArgumentParser,
    label: str,
) -> str:
    if inline is not None and file_path is not None:
        parser.error(f"Use either --{label} or --{label}-file, not both.")
    if file_path is not None:
        try:
            return file_path.read_text(encoding="utf-8")
        except OSError as exc:
            parser.error(f"Could not read {label} file: {exc}")
    if inline is not None:
        return inline
    if stdin_fallback and not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _campaign_to_dict(campaign: Campaign) -> dict[str, object]:
    return {
        "campaign_id": campaign.campaign_id,
        "name": campaign.name,
        "target": campaign.scope.target,
        "authorization": campaign.scope.authorization,
        "allowed_actions": list(campaign.scope.allowed_actions),
        "prohibited_actions": list(campaign.scope.prohibited_actions),
        "disclosure_requirements": list(campaign.scope.disclosure_requirements),
        "objective": campaign.objective,
        "success_criteria": list(campaign.success_criteria),
        "created_at": campaign.created_at,
    }


def _attempt_to_dict(attempt: Attempt) -> dict[str, object]:
    return {
        "attempt_id": attempt.attempt_id,
        "campaign_id": attempt.campaign_id,
        "attack_family": attempt.attack_family,
        "hypothesis": attempt.hypothesis,
        "payload": attempt.payload,
        "delivery_channel": attempt.delivery_channel,
        "result": attempt.result.value,
        "target_response": attempt.target_response,
        "tool_trace": list(attempt.tool_trace),
        "failure_reason": attempt.failure_reason,
        "lesson": attempt.lesson,
        "parent_attempt_id": attempt.parent_attempt_id,
        "created_at": attempt.created_at,
    }


if __name__ == "__main__":
    raise SystemExit(main())
