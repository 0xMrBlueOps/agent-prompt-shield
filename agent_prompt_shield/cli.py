from __future__ import annotations

import argparse
import json
import sys

from .audit import AuditLog
from .context import ShieldedContext
from .models import EnforcementResult, ToolRequest
from .scanner import PromptShield, ScannerConfig
from .tool_gate import POLICY_PROFILES, ToolGatekeeper, customize_policy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-prompt-shield")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan untrusted text.")
    scan.add_argument("--text", help="Text to scan. Defaults to stdin.")
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    scan.add_argument("--canary", action="append", default=[], help="Canary secret to detect.")
    scan.add_argument("--suspicious-threshold", type=int, default=25, help="Score needed for a suspicious verdict.")
    scan.add_argument("--blocked-threshold", type=int, default=60, help="Score needed for a blocked verdict.")
    scan.add_argument("--disable-rule", action="append", default=[], help="Disable a scanner rule by rule id.")
    scan.add_argument("--disable-category", action="append", default=[], help="Disable a scanner category.")
    scan.add_argument("--block-category", action="append", default=[], help="Always block when this category appears.")
    scan.add_argument(
        "--rule-severity",
        action="append",
        default=[],
        metavar="RULE=INT",
        help="Override a rule severity, for example role_override.new_role=10.",
    )
    scan.add_argument(
        "--category-severity",
        action="append",
        default=[],
        metavar="CATEGORY=INT",
        help="Override all findings in a category, for example obfuscation=40.",
    )
    scan.add_argument("--audit-log", help="Append scan and tool decisions to a JSONL audit log.")
    scan.add_argument("--tool", help="Optional tool name to gate against this scan result.")
    scan.add_argument(
        "--tool-args-json",
        default="{}",
        help="JSON object of proposed tool arguments used for risk classification.",
    )
    scan.add_argument("--risk", choices=["low", "medium", "high", "critical"], help="Override tool risk.")
    scan.add_argument(
        "--policy",
        default="balanced",
        choices=sorted(POLICY_PROFILES),
        help="Tool enforcement policy profile.",
    )
    scan.add_argument("--allow-tool", action="append", default=[], help="Allow tools matching this substring.")
    scan.add_argument("--deny-tool", action="append", default=[], help="Block tools matching this substring.")
    scan.add_argument("--approval-tool", action="append", default=[], help="Require approval for tools matching this substring.")

    context = subparsers.add_parser("context", help="Build and score mixed-trust prompt context.")
    context.add_argument(
        "--trusted",
        action="append",
        default=[],
        metavar="SOURCE=TEXT",
        help="Trusted context entry. May be repeated.",
    )
    context.add_argument(
        "--untrusted",
        action="append",
        default=[],
        metavar="SOURCE=TEXT",
        help="Untrusted context entry to scan and sanitize. May be repeated.",
    )
    context.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    context.add_argument("--audit-log", help="Append context scans and tool decisions to a JSONL audit log.")
    context.add_argument("--suspicious-threshold", type=int, default=25, help="Score needed for a suspicious verdict.")
    context.add_argument("--blocked-threshold", type=int, default=60, help="Score needed for a blocked verdict.")
    context.add_argument("--disable-rule", action="append", default=[], help="Disable a scanner rule by rule id.")
    context.add_argument("--disable-category", action="append", default=[], help="Disable a scanner category.")
    context.add_argument("--block-category", action="append", default=[], help="Always block when this category appears.")
    context.add_argument("--rule-severity", action="append", default=[], metavar="RULE=INT", help="Override a rule severity.")
    context.add_argument("--category-severity", action="append", default=[], metavar="CATEGORY=INT", help="Override a category severity.")
    context.add_argument("--tool", help="Optional tool name to gate against the combined context.")
    context.add_argument(
        "--tool-args-json",
        default="{}",
        help="JSON object of proposed tool arguments used for risk classification.",
    )
    context.add_argument("--risk", choices=["low", "medium", "high", "critical"], help="Override tool risk.")
    context.add_argument(
        "--policy",
        default="balanced",
        choices=sorted(POLICY_PROFILES),
        help="Tool enforcement policy profile.",
    )
    context.add_argument("--allow-tool", action="append", default=[], help="Allow tools matching this substring.")
    context.add_argument("--deny-tool", action="append", default=[], help="Block tools matching this substring.")
    context.add_argument("--approval-tool", action="append", default=[], help="Require approval for tools matching this substring.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        text = args.text if args.text is not None else sys.stdin.read()
        scanner_config = _scanner_config_from_args(args, parser)
        policy = customize_policy(
            args.policy,
            allow_tools=tuple(args.allow_tool),
            deny_tools=tuple(args.deny_tool),
            require_approval_tools=tuple(args.approval_tool),
        )
        shield = PromptShield(
            config=scanner_config,
            tool_gatekeeper=ToolGatekeeper(policy),
        )
        audit_log = AuditLog(args.audit_log) if args.audit_log else None
        result = shield.scan(text)
        if audit_log:
            audit_log.record_scan(result, source="cli.scan")
        payload = result.to_dict()
        if args.tool:
            try:
                tool_args = json.loads(args.tool_args_json)
            except json.JSONDecodeError as exc:
                parser.error(f"--tool-args-json must be valid JSON: {exc}")
            if not isinstance(tool_args, dict):
                parser.error("--tool-args-json must decode to a JSON object.")
            decision = shield.gate_tool(
                ToolRequest(name=args.tool, args=tool_args, risk=args.risk),
                result,
            )
            payload["tool_decision"] = decision.to_dict()
            if audit_log:
                audit_log.record_enforcement(
                    EnforcementResult(scan=result, decision=decision),
                    source="cli.scan",
                    metadata={"tool_name": args.tool, "tool_args": tool_args},
                )

        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(result.reason_summary())
            for finding in result.findings:
                print(f"- {finding.rule_id}: {finding.message} [{finding.evidence}]")
            if args.tool:
                decision = payload["tool_decision"]
                print(f"tool={decision['tool_name']} allowed={decision['allowed']} reason={decision['reason']}")
        return 2 if result.blocked else 1 if result.suspicious else 0

    if args.command == "context":
        scanner_config = _scanner_config_from_args(args, parser)
        policy = customize_policy(
            args.policy,
            allow_tools=tuple(args.allow_tool),
            deny_tools=tuple(args.deny_tool),
            require_approval_tools=tuple(args.approval_tool),
        )
        context = ShieldedContext(
            PromptShield(config=scanner_config, tool_gatekeeper=ToolGatekeeper(policy)),
            audit_log=args.audit_log,
        )
        for raw_entry in args.trusted:
            source, text = _split_context_entry(raw_entry)
            context.add_trusted(text, source=source)
        for raw_entry in args.untrusted:
            source, text = _split_context_entry(raw_entry)
            context.add_untrusted(text, source=source)

        report = context.report()
        payload = report.to_dict()
        payload["prompt_context"] = context.build_prompt_context()
        if args.tool:
            try:
                tool_args = json.loads(args.tool_args_json)
            except json.JSONDecodeError as exc:
                parser.error(f"--tool-args-json must be valid JSON: {exc}")
            if not isinstance(tool_args, dict):
                parser.error("--tool-args-json must decode to a JSON object.")
            payload["tool_decision"] = context.enforce_tool(
                tool_name=args.tool,
                tool_args=tool_args,
                risk=args.risk,
            ).decision.to_dict()

        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"context verdict={report.verdict.value} score={report.score}")
            print(payload["prompt_context"])
            if args.tool:
                decision = payload["tool_decision"]
                print(f"tool={decision['tool_name']} allowed={decision['allowed']} reason={decision['reason']}")
        return 2 if report.blocked else 1 if report.suspicious else 0

    parser.error(f"Unknown command: {args.command}")
    return 2


def _split_context_entry(raw_entry: str) -> tuple[str, str]:
    if "=" not in raw_entry:
        return "unknown", raw_entry
    source, text = raw_entry.split("=", 1)
    return source.strip() or "unknown", text


def _scanner_config_from_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> ScannerConfig:
    if args.suspicious_threshold < 0 or args.blocked_threshold < 0:
        parser.error("Thresholds must be non-negative integers.")
    if args.suspicious_threshold > args.blocked_threshold:
        parser.error("--suspicious-threshold cannot be greater than --blocked-threshold.")

    return ScannerConfig(
        suspicious_threshold=args.suspicious_threshold,
        blocked_threshold=args.blocked_threshold,
        canary_secrets=tuple(getattr(args, "canary", ())),
        disabled_rules=tuple(args.disable_rule),
        disabled_categories=tuple(args.disable_category),
        blocked_categories=tuple(args.block_category),
        rule_severity_overrides=_parse_severity_overrides(args.rule_severity, parser),
        category_severity_overrides=_parse_severity_overrides(args.category_severity, parser),
    )


def _parse_severity_overrides(
    raw_items: list[str],
    parser: argparse.ArgumentParser,
) -> dict[str, int]:
    overrides: dict[str, int] = {}
    for raw_item in raw_items:
        if "=" not in raw_item:
            parser.error(f"Severity override must use NAME=INT format: {raw_item}")
        name, raw_value = raw_item.split("=", 1)
        name = name.strip()
        if not name:
            parser.error(f"Severity override name cannot be empty: {raw_item}")
        try:
            value = int(raw_value)
        except ValueError:
            parser.error(f"Severity override must end with an integer: {raw_item}")
        if value < 0 or value > 100:
            parser.error(f"Severity override must be between 0 and 100: {raw_item}")
        overrides[name] = value
    return overrides


if __name__ == "__main__":
    raise SystemExit(main())
