from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .redlab import Attempt, Campaign, RedLabLedger
from .redlab_drafts import DraftStatus, DraftStore
from .redlab_verify import IndependentEvaluation, VerificationStore


@dataclass(frozen=True)
class CampaignReport:
    campaign: Campaign
    markdown: str

    def write(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.markdown, encoding="utf-8")
        return output


def build_campaign_report(ledger_path: str | Path, campaign_id: str) -> CampaignReport:
    ledger = RedLabLedger(ledger_path)
    verification = VerificationStore(ledger_path)
    drafts = DraftStore(ledger_path)
    campaign = _find_campaign(ledger, campaign_id)
    attempts = ledger.attempts(campaign_id)
    metrics = ledger.metrics(campaign_id)
    confirmed = [item for item in attempts if verification.confirmed_success(item.attempt_id)]
    pending_drafts = drafts.drafts(campaign_id=campaign_id, status=DraftStatus.PENDING)

    lines = [
        f"# Red Lab Campaign Report: {_safe_inline(campaign.name)}",
        "",
        "## Scope and authorization",
        "",
        f"- Campaign ID: {_safe_inline(campaign.campaign_id)}",
        f"- Created: {_safe_inline(campaign.created_at)}",
        "",
        *_labeled_literal("Target", campaign.scope.target),
        *_labeled_literal("Authorization", campaign.scope.authorization),
        *_labeled_literal("Objective", campaign.objective),
        "### Allowed actions",
        "",
        *(_safe_list(campaign.scope.allowed_actions) or ["- None declared"]),
        "",
        "### Prohibited actions",
        "",
        *(_safe_list(campaign.scope.prohibited_actions) or ["- None declared"]),
        "",
        "### Disclosure requirements",
        "",
        *(_safe_list(campaign.scope.disclosure_requirements) or ["- None declared"]),
        "",
        "### Success criteria",
        "",
        *_safe_list(campaign.success_criteria),
        "",
        "## Metrics",
        "",
        f"- Completed attempts: {metrics['attempts']}",
        f"- Pending attempts: {metrics['pending']}",
        f"- Successful: {metrics['successes']}",
        f"- Partial: {metrics['partials']}",
        f"- Failed: {metrics['failures']}",
        f"- Attack success rate: {metrics['attack_success_rate']:.2%}",
        f"- Partial-or-better rate: {metrics['partial_or_better_rate']:.2%}",
        f"- Confirmed reproducible successes: {len(confirmed)}",
        f"- Pending strategy drafts: {len(pending_drafts)}",
        "",
        "## Experiment history",
        "",
    ]

    if not attempts:
        lines.append("No attempts recorded.")
    else:
        for item in attempts:
            lines.extend(
                _attempt_section(
                    item,
                    verification.confirmed_success(item.attempt_id),
                    verification.evaluations(item.attempt_id),
                )
            )

    lines.extend(["", "## Confirmed findings", ""])
    if not confirmed:
        lines.append("No independently evaluated and replay-verified success has been confirmed.")
    else:
        for item in confirmed:
            lines.extend(
                [
                    f"### Attempt: {_safe_inline(item.attempt_id)}",
                    "",
                    *_labeled_literal("Attack family", item.attack_family),
                    *_labeled_literal("Hypothesis", item.hypothesis),
                    *_labeled_literal("Lesson", item.lesson or "Not recorded"),
                ]
            )

    lines.extend(
        [
            "",
            "## Reproducibility statement",
            "",
            "A finding is listed as confirmed only when the source attempt is successful, "
            "an exact criterion-complete independent evaluation is successful, and a passing "
            "same-campaign replay verification is present in the append-only ledger.",
            "",
        ]
    )
    return CampaignReport(campaign=campaign, markdown="\n".join(lines))


def _attempt_section(
    item: Attempt,
    confirmed: bool,
    evaluations: list[IndependentEvaluation],
) -> list[str]:
    status = item.result.value
    if confirmed:
        status += " (confirmed)"
    trace = json.dumps(list(item.tool_trace), ensure_ascii=False, indent=2)
    lines = [
        f"### Attempt: {_safe_inline(item.attempt_id)}",
        "",
        f"- Result: {_safe_inline(status)}",
        f"- Parent: {_safe_inline(item.parent_attempt_id or 'root')}",
        "",
        *_labeled_literal("Attack family", item.attack_family),
        *_labeled_literal("Delivery channel", item.delivery_channel),
        *_labeled_literal("Hypothesis", item.hypothesis),
        *_labeled_literal("Failure reason", item.failure_reason or "Not recorded"),
        *_labeled_literal("Lesson", item.lesson or "Not recorded"),
        *_labeled_literal("Payload", item.payload),
        *_labeled_literal(
            "Target response",
            item.target_response.strip() or "Not yet recorded",
        ),
        *_labeled_literal("Tool trace", trace),
    ]
    if not evaluations:
        lines.extend(["**Independent evaluations**", "", "None recorded.", ""])
    else:
        lines.extend(["**Independent evaluations**", ""])
        for evaluation in evaluations:
            lines.extend(
                [
                    f"- {_safe_inline(evaluation.evaluation_id)}: "
                    f"{_safe_inline(evaluation.verdict.value)} by "
                    f"{_safe_inline(evaluation.evaluator)}",
                    "",
                ]
            )
            for finding in evaluation.findings:
                lines.extend(
                    [
                        f"  - Criterion ({'met' if finding.met else 'not met'}): "
                        f"{_safe_inline(finding.criterion)}",
                        "",
                        *_labeled_literal("Evidence", finding.evidence),
                    ]
                )
            lines.extend(_labeled_literal("Rationale", evaluation.rationale))
    return lines


def _labeled_literal(label: str, value: str) -> list[str]:
    return [f"**{label}**", "", *_literal_block(value), ""]


def _literal_block(value: str) -> list[str]:
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return [f"    {line}" for line in lines]


def _safe_list(values: tuple[str, ...]) -> list[str]:
    return [f"- {_safe_inline(value)}" for value in values]


def _safe_inline(value: str) -> str:
    escaped = value
    for char in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "#", "|"):
        escaped = escaped.replace(char, f"\\{char}")
    return escaped.replace("\r", " ").replace("\n", " ")


def _find_campaign(ledger: RedLabLedger, campaign_id: str) -> Campaign:
    for item in ledger.campaigns():
        if item.campaign_id == campaign_id:
            return item
    raise ValueError(f"unknown campaign_id: {campaign_id}")
