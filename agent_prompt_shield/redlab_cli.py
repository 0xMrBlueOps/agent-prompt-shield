from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope
from .redlab_drafts import DraftStatus, DraftStore, StrategyDraft
from .redlab_model import EvaluationPacket, OpenAIResponsesEvaluator
from .redlab_strategy import (
    OpenAIResponsesStrategist,
    StrategyPacket,
    StrategyProposal,
    select_strategy_context,
)
from .redlab_verify import (
    CriterionFinding,
    EvaluationVerdict,
    IndependentEvaluation,
    ReplayVerification,
    VerificationStore,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-redlab",
        description="Evidence-driven CLI for authorized AI red-team campaigns.",
    )
    parser.add_argument("--ledger", default=".redlab/ledger.jsonl")
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

    record = subparsers.add_parser("record", help="Record an experiment and transcript.")
    record.add_argument("--campaign", required=True)
    record.add_argument("--family", required=True)
    record.add_argument("--hypothesis", required=True)
    record.add_argument("--payload")
    record.add_argument("--payload-file", type=Path)
    record.add_argument("--channel", required=True)
    record.add_argument("--result", required=True, choices=[item.value for item in AttemptResult])
    record.add_argument("--response")
    record.add_argument("--response-file", type=Path)
    record.add_argument("--failure-reason", default="")
    record.add_argument("--lesson", default="")
    record.add_argument("--parent")
    record.add_argument("--tool-trace-json", default="[]")

    evaluate = subparsers.add_parser("evaluate", help="Record an independent evaluation.")
    evaluate.add_argument("--campaign", required=True)
    evaluate.add_argument("--attempt", required=True)
    evaluate.add_argument("--evaluator", required=True)
    evaluate.add_argument("--verdict", required=True, choices=[item.value for item in EvaluationVerdict])
    evaluate.add_argument(
        "--finding",
        action="append",
        required=True,
        metavar="MET|CRITERION|EVIDENCE",
    )
    evaluate.add_argument("--rationale", required=True)

    evaluate_model = subparsers.add_parser("evaluate-model", help="Evaluate and record one attempt.")
    evaluate_model.add_argument("--attempt", required=True)
    evaluate_model.add_argument("--model", default="gpt-5.6")
    evaluate_model.add_argument("--evaluator")
    evaluate_model.add_argument("--base-url", default="https://api.openai.com/v1/responses")
    evaluate_model.add_argument("--timeout", type=float, default=90.0)
    evaluate_model.add_argument("--dry-run", action="store_true")

    strategy = subparsers.add_parser(
        "strategy",
        help="Generate controlled next-step proposals and save them as pending drafts.",
    )
    strategy.add_argument("--attempt", required=True, help="Failed or partial focus attempt.")
    strategy.add_argument("--model", default="gpt-5.6")
    strategy.add_argument("--max-proposals", type=int, default=3)
    strategy.add_argument("--max-history", type=int, default=12)
    strategy.add_argument("--base-url", default="https://api.openai.com/v1/responses")
    strategy.add_argument("--timeout", type=float, default=90.0)
    strategy.add_argument("--dry-run", action="store_true")

    drafts = subparsers.add_parser("drafts", help="List strategy drafts.")
    drafts.add_argument("--campaign")
    drafts.add_argument("--status", choices=[item.value for item in DraftStatus])
    drafts.add_argument("--json", action="store_true")

    accept = subparsers.add_parser("accept-draft", help="Accept a draft as an unexecuted child attempt.")
    accept.add_argument("--draft", required=True)
    accept.add_argument("--channel", required=True)

    reject = subparsers.add_parser("reject-draft", help="Reject a pending strategy draft.")
    reject.add_argument("--draft", required=True)
    reject.add_argument("--reason", required=True)

    replay = subparsers.add_parser("verify-replay", help="Verify fresh replay attempts.")
    replay.add_argument("--campaign", required=True)
    replay.add_argument("--source", required=True)
    replay.add_argument("--replay", action="append", required=True)
    replay.add_argument("--required-successes", type=int, default=1)
    replay.add_argument("--verifier", required=True)

    status = subparsers.add_parser("status", help="Show evaluation and confirmation status.")
    status.add_argument("--attempt", required=True)

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
    verification = VerificationStore(args.ledger)
    draft_store = DraftStore(args.ledger)

    if args.command == "init":
        item = ledger.create_campaign(
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
        print(json.dumps(_campaign_to_dict(item), indent=2))
        return 0

    if args.command == "record":
        payload = _read_text_argument(args.payload, args.payload_file, True, parser, "payload")
        response = _read_text_argument(args.response, args.response_file, False, parser, "response")
        try:
            raw_trace = json.loads(args.tool_trace_json)
        except json.JSONDecodeError as exc:
            parser.error(f"--tool-trace-json must be valid JSON: {exc}")
        if not isinstance(raw_trace, list) or not all(isinstance(item, dict) for item in raw_trace):
            parser.error("--tool-trace-json must decode to an array of objects.")
        item = ledger.record_attempt(
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
        print(json.dumps(_attempt_to_dict(item), indent=2))
        return 0

    if args.command == "evaluate":
        findings = tuple(_parse_finding(raw, parser) for raw in args.finding)
        item = verification.record_evaluation(
            IndependentEvaluation(
                campaign_id=args.campaign,
                attempt_id=args.attempt,
                evaluator=args.evaluator,
                verdict=EvaluationVerdict(args.verdict),
                findings=findings,
                rationale=args.rationale,
            )
        )
        print(json.dumps(_evaluation_to_dict(item), indent=2))
        return 0

    if args.command == "evaluate-model":
        attempt = _find_attempt(ledger, args.attempt, parser)
        campaign = _find_campaign(ledger, attempt.campaign_id, parser)
        evaluator = OpenAIResponsesEvaluator(
            model=args.model,
            base_url=args.base_url,
            timeout_seconds=args.timeout,
        )
        packet = EvaluationPacket(campaign=campaign, attempt=attempt)
        if args.dry_run:
            print(json.dumps(evaluator.build_request(packet), indent=2))
            return 0
        item = evaluator.evaluate(packet, evaluator_identity=args.evaluator)
        verification.record_evaluation(item)
        print(json.dumps(_evaluation_to_dict(item), indent=2))
        return 0

    if args.command == "strategy":
        focus = _find_attempt(ledger, args.attempt, parser)
        if focus.result not in {AttemptResult.FAILED, AttemptResult.PARTIAL}:
            parser.error("strategy focus must be a failed or partial attempt")
        campaign = _find_campaign(ledger, focus.campaign_id, parser)
        try:
            context = select_strategy_context(
                ledger.attempts(focus.campaign_id),
                focus.attempt_id,
                max_history=args.max_history,
            )
            packet = StrategyPacket(
                campaign=campaign,
                attempts=context,
                focus_attempt_id=focus.attempt_id,
                max_proposals=args.max_proposals,
            )
        except ValueError as exc:
            parser.error(str(exc))
        strategist = OpenAIResponsesStrategist(
            model=args.model,
            base_url=args.base_url,
            timeout_seconds=args.timeout,
        )
        if args.dry_run:
            print(json.dumps(strategist.build_request(packet), indent=2))
            return 0
        analysis, proposals = strategist.propose(packet)
        created = draft_store.create_drafts(
            campaign_id=campaign.campaign_id,
            analysis=analysis,
            proposals=proposals,
        )
        print(json.dumps({"analysis": analysis, "drafts": [_draft_to_dict(item) for item in created]}, indent=2))
        return 0

    if args.command == "drafts":
        status_filter = DraftStatus(args.status) if args.status else None
        items = draft_store.drafts(campaign_id=args.campaign, status=status_filter)
        if args.json:
            print(json.dumps([_draft_to_dict(item) for item in items], indent=2))
        else:
            for item in items:
                print(
                    f"{item.draft_id}\t{item.status.value}\t{item.proposal.action.value}"
                    f"\t{item.proposal.title}\tparent={item.proposal.parent_attempt_id}"
                )
        return 0

    if args.command == "accept-draft":
        item = draft_store.accept(args.draft, delivery_channel=args.channel)
        print(json.dumps(_attempt_to_dict(item), indent=2))
        return 0

    if args.command == "reject-draft":
        item = draft_store.reject(args.draft, reason=args.reason)
        print(json.dumps(_draft_to_dict(item), indent=2))
        return 0

    if args.command == "verify-replay":
        result = verification.record_replay(
            ReplayVerification(
                campaign_id=args.campaign,
                source_attempt_id=args.source,
                replay_attempt_ids=tuple(args.replay),
                required_successes=args.required_successes,
                verifier=args.verifier,
            )
        )
        print(json.dumps(result, indent=2))
        return 0 if result["passed"] else 1

    if args.command == "status":
        payload = {
            "attempt_id": args.attempt,
            "confirmed_success": verification.confirmed_success(args.attempt),
            "evaluations": [_evaluation_to_dict(item) for item in verification.evaluations(args.attempt)],
            "replay_verifications": verification.replay_verifications(args.attempt),
        }
        print(json.dumps(payload, indent=2))
        return 0 if payload["confirmed_success"] else 1

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
                print(
                    f"{item.attempt_id}\t{item.result.value}\t{item.attack_family}"
                    f"\tparent={item.parent_attempt_id or 'root'}"
                )
        return 0

    if args.command == "metrics":
        print(json.dumps(ledger.metrics(args.campaign), indent=2))
        return 0

    parser.error(f"Unknown command: {args.command}")


def _find_attempt(ledger: RedLabLedger, attempt_id: str, parser: argparse.ArgumentParser) -> Attempt:
    for item in ledger.attempts():
        if item.attempt_id == attempt_id:
            return item
    parser.error(f"Unknown attempt id: {attempt_id}")


def _find_campaign(ledger: RedLabLedger, campaign_id: str, parser: argparse.ArgumentParser) -> Campaign:
    for item in ledger.campaigns():
        if item.campaign_id == campaign_id:
            return item
    parser.error(f"Unknown campaign id: {campaign_id}")


def _parse_finding(raw: str, parser: argparse.ArgumentParser) -> CriterionFinding:
    parts = raw.split("|", 2)
    if len(parts) != 3:
        parser.error("--finding must use MET|CRITERION|EVIDENCE format.")
    raw_met, criterion, evidence = parts
    normalized = raw_met.strip().lower()
    if normalized not in {"true", "false"}:
        parser.error("--finding MET value must be true or false.")
    return CriterionFinding(criterion=criterion, met=normalized == "true", evidence=evidence)


def _read_text_argument(
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


def _campaign_to_dict(item: Campaign) -> dict[str, object]:
    return {
        "campaign_id": item.campaign_id,
        "name": item.name,
        "target": item.scope.target,
        "authorization": item.scope.authorization,
        "allowed_actions": list(item.scope.allowed_actions),
        "prohibited_actions": list(item.scope.prohibited_actions),
        "disclosure_requirements": list(item.scope.disclosure_requirements),
        "objective": item.objective,
        "success_criteria": list(item.success_criteria),
        "created_at": item.created_at,
    }


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


def _evaluation_to_dict(item: IndependentEvaluation) -> dict[str, object]:
    return {
        "evaluation_id": item.evaluation_id,
        "campaign_id": item.campaign_id,
        "attempt_id": item.attempt_id,
        "evaluator": item.evaluator,
        "verdict": item.verdict.value,
        "findings": [
            {"criterion": finding.criterion, "met": finding.met, "evidence": finding.evidence}
            for finding in item.findings
        ],
        "rationale": item.rationale,
        "created_at": item.created_at,
    }


def _proposal_to_dict(item: StrategyProposal) -> dict[str, object]:
    return {
        "title": item.title,
        "action": item.action.value,
        "attack_family": item.attack_family,
        "hypothesis": item.hypothesis,
        "controlled_change": item.controlled_change,
        "proposed_payload": item.proposed_payload,
        "expected_signal": item.expected_signal,
        "stop_condition": item.stop_condition,
        "parent_attempt_id": item.parent_attempt_id,
    }


def _draft_to_dict(item: StrategyDraft) -> dict[str, object]:
    return {
        "draft_id": item.draft_id,
        "campaign_id": item.campaign_id,
        "status": item.status.value,
        "analysis": item.analysis,
        "proposal": _proposal_to_dict(item.proposal),
        "created_at": item.created_at,
    }


if __name__ == "__main__":
    raise SystemExit(main())
