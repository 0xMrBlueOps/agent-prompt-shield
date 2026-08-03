from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope
from .redlab_drafts import DraftStatus, DraftStore, StrategyDraft
from .redlab_model import EvaluationPacket, OpenAIResponsesEvaluator
from .redlab_report import build_campaign_report
from .redlab_strategy import (
    OpenAIResponsesStrategist,
    StrategyPacket,
    StrategyProposal,
    select_strategy_context,
)
from .redlab_tournament import (
    DEFAULT_LENSES,
    CandidateScore,
    StrategyLens,
    StrategyTournament,
    TournamentCandidate,
    TournamentConfig,
    load_seed_material,
    parse_labeled_payload,
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
    evaluate.add_argument(
        "--verdict", required=True, choices=[item.value for item in EvaluationVerdict]
    )
    evaluate.add_argument(
        "--finding",
        action="append",
        required=True,
        metavar="MET|CRITERION|EVIDENCE",
    )
    evaluate.add_argument("--rationale", required=True)

    evaluate_model = subparsers.add_parser(
        "evaluate-model", help="Evaluate and record one attempt."
    )
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
    strategy.add_argument("--max-output-tokens", type=int, default=6_000)
    strategy.add_argument("--base-url", default="https://api.openai.com/v1/responses")
    strategy.add_argument("--timeout", type=float, default=90.0)
    strategy.add_argument("--dry-run", action="store_true")

    tournament = subparsers.add_parser(
        "strategy-tournament",
        help="Generate, deduplicate, and independently rank multi-lens strategy proposals.",
    )
    tournament.add_argument("--attempt", required=True, help="Failed or partial focus attempt.")
    tournament.add_argument("--model", default="gpt-5.6")
    tournament.add_argument("--critic-model")
    tournament.add_argument(
        "--lens",
        action="append",
        choices=[item.value for item in StrategyLens],
        help="Generation lens. Repeat for multiple lenses; defaults to four complementary lenses.",
    )
    tournament.add_argument("--proposals-per-lens", type=int, default=3)
    tournament.add_argument("--finalists", type=int, default=3)
    tournament.add_argument("--max-history", type=int, default=12)
    tournament.add_argument("--max-api-calls", type=int, default=9)
    tournament.add_argument("--max-output-tokens", type=int, default=6_000)
    tournament.add_argument("--seed-file", action="append", type=Path, default=[])
    tournament.add_argument("--base-url", default="https://api.openai.com/v1/responses")
    tournament.add_argument("--timeout", type=float, default=90.0)
    tournament.add_argument("--dry-run", action="store_true")

    drafts = subparsers.add_parser("drafts", help="List strategy drafts.")
    drafts.add_argument("--campaign")
    drafts.add_argument("--status", choices=[item.value for item in DraftStatus])
    drafts.add_argument("--json", action="store_true")

    accept = subparsers.add_parser(
        "accept-draft", help="Accept a draft as an unexecuted child attempt."
    )
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

    complete = subparsers.add_parser(
        "complete-attempt",
        help="Complete a pending attempt with its final evidence.",
    )
    complete.add_argument("--attempt", required=True)
    complete.add_argument(
        "--result",
        required=True,
        choices=[
            AttemptResult.FAILED.value,
            AttemptResult.PARTIAL.value,
            AttemptResult.SUCCESSFUL.value,
        ],
    )
    complete.add_argument("--response")
    complete.add_argument("--response-file", type=Path)
    complete.add_argument("--tool-trace-json", default="[]")
    complete.add_argument("--failure-reason", default="")
    complete.add_argument("--lesson", default="")

    report = subparsers.add_parser("report", help="Render a campaign Markdown report.")
    report.add_argument("--campaign", required=True)
    report.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ledger = RedLabLedger(args.ledger)
    verification = VerificationStore(args.ledger)
    draft_store = DraftStore(args.ledger)

    if args.command == "init":
        created_campaign = ledger.create_campaign(
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
        print(json.dumps(_campaign_to_dict(created_campaign), indent=2))
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
        recorded_attempt = ledger.record_attempt(
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
        print(json.dumps(_attempt_to_dict(recorded_attempt), indent=2))
        return 0

    if args.command == "complete-attempt":
        response = _read_text_argument(
            args.response,
            args.response_file,
            True,
            parser,
            "response",
        )
        try:
            raw_trace = json.loads(args.tool_trace_json)
        except json.JSONDecodeError as exc:
            parser.error(f"--tool-trace-json must be valid JSON: {exc}")
        if not isinstance(raw_trace, list) or not all(isinstance(item, dict) for item in raw_trace):
            parser.error("--tool-trace-json must decode to an array of objects.")
        try:
            completed_attempt = ledger.complete_attempt(
                args.attempt,
                result=AttemptResult(args.result),
                target_response=response,
                tool_trace=tuple(raw_trace),
                failure_reason=args.failure_reason,
                lesson=args.lesson,
            )
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(_attempt_to_dict(completed_attempt), indent=2))
        return 0

    if args.command == "evaluate":
        findings = tuple(_parse_finding(raw, parser) for raw in args.finding)
        recorded_evaluation = verification.record_evaluation(
            IndependentEvaluation(
                campaign_id=args.campaign,
                attempt_id=args.attempt,
                evaluator=args.evaluator,
                verdict=EvaluationVerdict(args.verdict),
                findings=findings,
                rationale=args.rationale,
            )
        )
        print(json.dumps(_evaluation_to_dict(recorded_evaluation), indent=2))
        return 0

    if args.command == "evaluate-model":
        evaluated_attempt = _find_attempt(ledger, args.attempt, parser)
        evaluation_campaign = _find_campaign(
            ledger,
            evaluated_attempt.campaign_id,
            parser,
        )
        evaluator = OpenAIResponsesEvaluator(
            model=args.model,
            base_url=args.base_url,
            timeout_seconds=args.timeout,
        )
        evaluation_packet = EvaluationPacket(
            campaign=evaluation_campaign,
            attempt=evaluated_attempt,
        )
        if args.dry_run:
            print(json.dumps(evaluator.build_request(evaluation_packet), indent=2))
            return 0
        model_evaluation = evaluator.evaluate(
            evaluation_packet,
            evaluator_identity=args.evaluator,
        )
        verification.record_evaluation(model_evaluation)
        print(json.dumps(_evaluation_to_dict(model_evaluation), indent=2))
        return 0

    if args.command == "strategy":
        focus = _find_attempt(ledger, args.attempt, parser)
        if focus.result not in {AttemptResult.FAILED, AttemptResult.PARTIAL}:
            parser.error("strategy focus must be a failed or partial attempt")
        strategy_campaign = _find_campaign(ledger, focus.campaign_id, parser)
        try:
            context = select_strategy_context(
                ledger.attempts(focus.campaign_id),
                focus.attempt_id,
                max_history=args.max_history,
            )
            strategy_packet = StrategyPacket(
                campaign=strategy_campaign,
                attempts=context,
                focus_attempt_id=focus.attempt_id,
                max_proposals=args.max_proposals,
            )
        except ValueError as exc:
            parser.error(str(exc))
        try:
            strategist = OpenAIResponsesStrategist(
                model=args.model,
                base_url=args.base_url,
                timeout_seconds=args.timeout,
                max_output_tokens=args.max_output_tokens,
            )
        except ValueError as exc:
            parser.error(str(exc))
        if args.dry_run:
            print(json.dumps(strategist.build_request(strategy_packet), indent=2))
            return 0
        analysis, proposals = strategist.propose(strategy_packet)
        created = draft_store.create_drafts(
            campaign_id=strategy_campaign.campaign_id,
            analysis=analysis,
            proposals=proposals,
        )
        print(
            json.dumps(
                {"analysis": analysis, "drafts": [_draft_to_dict(item) for item in created]},
                indent=2,
            )
        )
        return 0

    if args.command == "strategy-tournament":
        focus = _find_attempt(ledger, args.attempt, parser)
        if focus.result not in {AttemptResult.FAILED, AttemptResult.PARTIAL}:
            parser.error("strategy tournament focus must be a failed or partial attempt")
        strategy_campaign = _find_campaign(ledger, focus.campaign_id, parser)
        try:
            lenses = (
                tuple(StrategyLens(value) for value in args.lens)
                if args.lens
                else DEFAULT_LENSES
            )
            config = TournamentConfig(
                lenses=lenses,
                proposals_per_lens=args.proposals_per_lens,
                finalists=args.finalists,
            )
            config.validate()
            if args.max_api_calls < 1:
                raise ValueError("max_api_calls must be at least 1")
            if config.planned_api_calls > args.max_api_calls:
                raise ValueError(
                    f"strategy tournament plans {config.planned_api_calls} API calls, "
                    f"exceeding --max-api-calls {args.max_api_calls}"
                )
            context = select_strategy_context(
                ledger.attempts(focus.campaign_id),
                focus.attempt_id,
                max_history=args.max_history,
            )
            strategy_packet = StrategyPacket(
                campaign=strategy_campaign,
                attempts=context,
                focus_attempt_id=focus.attempt_id,
                max_proposals=args.proposals_per_lens,
            )
            seed_material = load_seed_material(tuple(args.seed_file))
            prior_payloads = _campaign_payloads(
                ledger,
                draft_store,
                strategy_campaign.campaign_id,
            )
            strategist = OpenAIResponsesStrategist(
                model=args.model,
                base_url=args.base_url,
                timeout_seconds=args.timeout,
                max_output_tokens=args.max_output_tokens,
            )
            strategy_tournament = StrategyTournament(
                strategist,
                critic_model=args.critic_model,
            )
            generation_requests = strategy_tournament.build_generation_requests(
                strategy_packet,
                config,
                seed_material=seed_material,
                excluded_payloads=prior_payloads,
            )
        except (RuntimeError, ValueError) as exc:
            parser.error(str(exc))
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "planned_api_calls": config.planned_api_calls,
                        "max_planned_output_tokens": (
                            config.planned_api_calls * strategist.max_output_tokens
                        ),
                        "generation_calls": len(config.lenses),
                        "critic_calls": 1,
                        "critic_model": strategy_tournament.critic_model,
                        "seed_items": len(seed_material),
                        "excluded_payloads": len(prior_payloads),
                        "generation_requests": generation_requests,
                    },
                    indent=2,
                )
            )
            return 0
        try:
            tournament_result = strategy_tournament.run(
                strategy_packet,
                config,
                seed_material=seed_material,
                excluded_payloads=prior_payloads,
            )
            created = draft_store.create_drafts(
                campaign_id=strategy_campaign.campaign_id,
                analysis=(
                    f"{tournament_result.summary} "
                    f"Critic analysis: {tournament_result.critic_analysis}"
                ),
                proposals=tuple(item.proposal for item in tournament_result.finalists),
            )
        except (RuntimeError, ValueError) as exc:
            parser.error(str(exc))
        score_by_id = {
            item.candidate_id: item for item in tournament_result.rankings
        }
        rank_by_id = {
            item.candidate_id: rank
            for rank, item in enumerate(tournament_result.ranked_candidates, start=1)
        }
        draft_by_fingerprint = {
            candidate.fingerprint: draft
            for candidate, draft in zip(tournament_result.finalists, created, strict=True)
        }
        print(
            json.dumps(
                {
                    "campaign_id": tournament_result.campaign_id,
                    "focus_attempt_id": tournament_result.focus_attempt_id,
                    "planned_api_calls": tournament_result.planned_api_calls,
                    "generation_analyses": [
                        {"lens": lens.value, "analysis": analysis}
                        for lens, analysis in tournament_result.generation_analyses
                    ],
                    "critic_analysis": tournament_result.critic_analysis,
                    "candidates": [
                        _tournament_candidate_to_dict(
                            item,
                            score_by_id[item.candidate_id],
                            rank=rank_by_id[item.candidate_id],
                            selected=item.fingerprint in draft_by_fingerprint,
                            draft=draft_by_fingerprint.get(item.fingerprint),
                        )
                        for item in tournament_result.candidates
                    ],
                    "drafts": [_draft_to_dict(item) for item in created],
                },
                indent=2,
            )
        )
        return 0

    if args.command == "drafts":
        status_filter = DraftStatus(args.status) if args.status else None
        draft_items = draft_store.drafts(
            campaign_id=args.campaign,
            status=status_filter,
        )
        if args.json:
            print(
                json.dumps(
                    [_draft_to_dict(draft) for draft in draft_items],
                    indent=2,
                )
            )
        else:
            for draft in draft_items:
                print(
                    f"{draft.draft_id}\t{draft.status.value}\t"
                    f"{draft.proposal.action.value}\t{draft.proposal.title}"
                    f"\tparent={draft.proposal.parent_attempt_id}"
                )
        return 0

    if args.command == "accept-draft":
        accepted_attempt = draft_store.accept(
            args.draft,
            delivery_channel=args.channel,
        )
        print(json.dumps(_attempt_to_dict(accepted_attempt), indent=2))
        return 0

    if args.command == "reject-draft":
        rejected_draft = draft_store.reject(args.draft, reason=args.reason)
        print(json.dumps(_draft_to_dict(rejected_draft), indent=2))
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
        status_payload = {
            "attempt_id": args.attempt,
            "confirmed_success": verification.confirmed_success(args.attempt),
            "evaluations": [
                _evaluation_to_dict(item) for item in verification.evaluations(args.attempt)
            ],
            "replay_verifications": verification.replay_verifications(args.attempt),
        }
        print(json.dumps(status_payload, indent=2))
        return 0 if status_payload["confirmed_success"] else 1

    if args.command == "campaigns":
        campaign_items = ledger.campaigns()
        if args.json:
            print(
                json.dumps(
                    [_campaign_to_dict(campaign) for campaign in campaign_items],
                    indent=2,
                )
            )
        else:
            for campaign in campaign_items:
                print(f"{campaign.campaign_id}\t{campaign.name}\t{campaign.scope.target}")
        return 0

    if args.command == "attempts":
        attempt_items = ledger.attempts(args.campaign)
        if args.json:
            print(
                json.dumps(
                    [_attempt_to_dict(attempt) for attempt in attempt_items],
                    indent=2,
                )
            )
        else:
            for attempt in attempt_items:
                print(
                    f"{attempt.attempt_id}\t{attempt.result.value}\t"
                    f"{attempt.attack_family}"
                    f"\tparent={attempt.parent_attempt_id or 'root'}"
                )
        return 0

    if args.command == "metrics":
        print(json.dumps(ledger.metrics(args.campaign), indent=2))
        return 0

    if args.command == "report":
        try:
            report = build_campaign_report(args.ledger, args.campaign)
        except ValueError as exc:
            parser.error(str(exc))
        if args.output is None:
            print(report.markdown)
        else:
            path = report.write(args.output)
            print(
                json.dumps(
                    {"campaign_id": args.campaign, "output": str(path)},
                    indent=2,
                )
            )
        return 0

    parser.error(f"Unknown command: {args.command}")


def _find_attempt(
    ledger: RedLabLedger, attempt_id: str, parser: argparse.ArgumentParser
) -> Attempt:
    for item in ledger.attempts():
        if item.attempt_id == attempt_id:
            return item
    parser.error(f"Unknown attempt id: {attempt_id}")


def _find_campaign(
    ledger: RedLabLedger, campaign_id: str, parser: argparse.ArgumentParser
) -> Campaign:
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
    payload: dict[str, object] = {
        "title": item.title,
        "action": item.action.value,
        "attack_family": item.attack_family,
        "hypothesis": item.hypothesis,
        "controlled_change": item.controlled_change,
        "proposed_payload": item.proposed_payload,
        "expected_signal": item.expected_signal,
        "stop_condition": item.stop_condition,
        "parent_attempt_id": item.parent_attempt_id,
        "action_tags": list(item.action_tags),
    }
    parsed_fields = parse_labeled_payload(item.proposed_payload)
    if parsed_fields:
        payload["payload_fields"] = parsed_fields
    return payload


def _campaign_payloads(
    ledger: RedLabLedger,
    draft_store: DraftStore,
    campaign_id: str,
) -> tuple[str, ...]:
    payloads = [
        item.payload
        for item in ledger.attempts(campaign_id)
        if item.payload.strip()
    ]
    payloads.extend(
        item.proposal.proposed_payload
        for item in draft_store.drafts(campaign_id=campaign_id)
        if item.proposal.proposed_payload.strip()
    )
    return tuple(dict.fromkeys(payloads))[-64:]


def _tournament_candidate_to_dict(
    item: TournamentCandidate,
    score: CandidateScore,
    *,
    rank: int,
    selected: bool,
    draft: StrategyDraft | None,
) -> dict[str, object]:
    score_payload = {
        "evidence_fit": score.evidence_fit,
        "scope_fidelity": score.scope_fidelity,
        "novelty": score.novelty,
        "testability": score.testability,
        "information_gain": score.information_gain,
        "weighted_score": score.weighted_score,
        "rationale": score.rationale,
        "risk": score.risk,
    }
    return {
        "candidate_id": item.candidate_id,
        "lens": item.lens.value,
        "fingerprint": item.fingerprint,
        "rank": rank,
        "selected": selected,
        "draft_id": draft.draft_id if draft else None,
        "score": score_payload,
        "proposal": _proposal_to_dict(item.proposal),
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
