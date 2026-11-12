from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .redlab import Campaign
    from .redlab_strategy import StrategyProposal

_NON_TAG = re.compile(r"[^a-z0-9]+")


def normalize_action_tag(value: str) -> str:
    tag = _NON_TAG.sub("-", value.strip().lower()).strip("-")
    if not tag:
        raise ValueError("scope action must contain letters or numbers")
    return tag


def validate_proposal_scope(campaign: Campaign, proposal: StrategyProposal) -> None:
    """Apply deterministic tag matching; this does not claim semantic policy understanding."""
    if proposal.action.value == "stop":
        if proposal.action_tags:
            raise ValueError("STOP proposals must not declare executable action tags")
        return
    if not proposal.action_tags:
        raise ValueError("executable proposal requires at least one action tag")

    normalized = tuple(normalize_action_tag(item) for item in proposal.action_tags)
    if normalized != proposal.action_tags:
        raise ValueError("proposal action tags must already be normalized")
    if len(set(normalized)) != len(normalized):
        raise ValueError("proposal action tags must be unique")

    allowed = {normalize_action_tag(item) for item in campaign.scope.allowed_actions}
    prohibited = {normalize_action_tag(item) for item in campaign.scope.prohibited_actions}
    blocked = sorted(set(normalized) & prohibited)
    if blocked:
        raise ValueError(f"proposal requests prohibited action tags: {', '.join(blocked)}")
    outside = sorted(set(normalized) - allowed)
    if outside:
        raise ValueError(f"proposal action tags are outside campaign scope: {', '.join(outside)}")
