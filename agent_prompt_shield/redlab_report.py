from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .redlab import Attempt, Campaign, RedLabLedger
from .redlab_drafts import DraftStatus, DraftStore
from .redlab_verify import VerificationStore


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
        f"# Red Lab Campaign Report: {campaign.name}",
        "",
        "## Scope and authorization",
        "",
        f"- Campaign ID: `{campaign.campaign_id}`",
        f"- Target: {campaign.scope.target}",
        f"- Authorization: {campaign.scope.authorization}",
        f"- Objective: {campaign.objective}",
        f"- Created: {campaign.created_at}",
        "",
        "### Allowed actions",
        "",
        *[f"- {item}" for item in campaign.scope.allowed_actions],
        "",
        "### Prohibited actions",
        "",
        *([f"- {item}" for item in campaign.scope.prohibited_actions] or ["- None declared"]),
        "",
        "### Success criteria",
        "",
        *[f"- {item}" for item in campaign.success_criteria],
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
            lines.extend(_attempt_section(item, verification.confirmed_success(item.attempt_id)))

    lines.extend(["", "## Confirmed findings", ""])
    if not confirmed:
        lines.append("No independently evaluated and replay-verified success has been confirmed.")
    else:
        for item in confirmed:
            lines.extend(
                [
                    f"### {item.attempt_id}",
                    "",
                    f"- Family: {item.attack_family}",
                    f"- Hypothesis: {item.hypothesis}",
                    f"- Lesson: {item.lesson or 'Not recorded'}",
                    "",
                ]
            )

    lines.extend(
        [
            "",
            "## Reproducibility statement",
            "",
            "A finding is listed as confirmed only when an independent criterion-level evaluation "
            "and a passing replay verification are both present in the append-only ledger.",
            "",
        ]
    )
    return CampaignReport(campaign=campaign, markdown="\n".join(lines))


def _attempt_section(item: Attempt, confirmed: bool) -> list[str]:
    status = item.result.value
    if confirmed:
        status += " (confirmed)"
    response = item.target_response.strip() or "Not yet recorded"
    failure = item.failure_reason.strip() or "Not recorded"
    lesson = item.lesson.strip() or "Not recorded"
    return [
        f"### {item.attempt_id}",
        "",
        f"- Result: {status}",
        f"- Parent: `{item.parent_attempt_id or 'root'}`",
        f"- Attack family: {item.attack_family}",
        f"- Delivery channel: {item.delivery_channel}",
        f"- Hypothesis: {item.hypothesis}",
        f"- Failure reason: {failure}",
        f"- Lesson: {lesson}",
        "",
        "**Payload**",
        "",
        "```text",
        item.payload,
        "```",
        "",
        "**Target response**",
        "",
        "```text",
        response,
        "```",
        "",
    ]


def _find_campaign(ledger: RedLabLedger, campaign_id: str) -> Campaign:
    for item in ledger.campaigns():
        if item.campaign_id == campaign_id:
            return item
    raise ValueError(f"unknown campaign_id: {campaign_id}")
