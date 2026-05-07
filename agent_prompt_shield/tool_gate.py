from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import GateDecision, ScanResult, ToolRequest, ToolRisk, Verdict


RISK_ORDER = {
    ToolRisk.LOW: 0,
    ToolRisk.MEDIUM: 1,
    ToolRisk.HIGH: 2,
    ToolRisk.CRITICAL: 3,
}


@dataclass(frozen=True)
class ToolPolicy:
    name: str = "balanced"
    block_on_verdict: Verdict = Verdict.BLOCKED
    block_risk_at_suspicious: ToolRisk = ToolRisk.HIGH
    approval_risk_at_suspicious: ToolRisk = ToolRisk.MEDIUM
    approval_risk_at_safe: ToolRisk | None = ToolRisk.CRITICAL
    allow_tools: tuple[str, ...] = ()
    deny_tools: tuple[str, ...] = ()
    require_approval_tools: tuple[str, ...] = ()
    critical_tools: tuple[str, ...] = (
        "email",
        "gmail",
        "outlook",
        "slack",
        "teams",
        "github",
        "http",
        "webhook",
        "post",
        "publish",
        "deploy",
        "payment",
        "cloud",
    )
    high_risk_tools: tuple[str, ...] = (
        "shell",
        "terminal",
        "powershell",
        "cmd",
        "bash",
        "filesystem",
        "file",
        "browser",
        "desktop_browser",
        "computer_use",
        "mcp",
    )
    medium_risk_tools: tuple[str, ...] = (
        "calendar",
        "drive",
        "notion",
        "linear",
        "database",
        "db",
        "memory",
    )
    write_arg_names: tuple[str, ...] = (
        "body",
        "content",
        "command",
        "message",
        "path",
        "query",
        "text",
        "url",
    )


POLICY_PROFILES: dict[str, ToolPolicy] = {
    "strict": ToolPolicy(
        name="strict",
        block_risk_at_suspicious=ToolRisk.MEDIUM,
        approval_risk_at_suspicious=ToolRisk.LOW,
        approval_risk_at_safe=ToolRisk.HIGH,
    ),
    "balanced": ToolPolicy(),
    "permissive": ToolPolicy(
        name="permissive",
        block_risk_at_suspicious=ToolRisk.CRITICAL,
        approval_risk_at_suspicious=ToolRisk.HIGH,
        approval_risk_at_safe=None,
    ),
}


class ToolGatekeeper:
    def __init__(self, policy: ToolPolicy | str | None = None) -> None:
        if isinstance(policy, str):
            self.policy = get_policy_profile(policy)
        else:
            self.policy = policy or get_policy_profile("balanced")

    def evaluate(self, request: ToolRequest, scan_result: ScanResult) -> GateDecision:
        tool_name = request.name.lower()
        risk = self.classify(request)

        if self._matches(tool_name, self.policy.deny_tools):
            return GateDecision(
                allowed=False,
                reason=f"Blocked {request.name} because it matches the policy deny list.",
                tool_name=request.name,
                scan_verdict=scan_result.verdict,
                risk=risk,
                profile=self.policy.name,
                matched_rule="tool.deny",
            )

        if scan_result.verdict == self.policy.block_on_verdict:
            return GateDecision(
                allowed=False,
                reason=f"Blocked {request.name} because the context verdict is {scan_result.verdict.value}.",
                tool_name=request.name,
                scan_verdict=scan_result.verdict,
                risk=risk,
                profile=self.policy.name,
                matched_rule="verdict.blocked",
            )

        if self._matches(tool_name, self.policy.allow_tools):
            return GateDecision(
                allowed=True,
                reason=f"Allowed {request.name} because it matches the policy allow list.",
                tool_name=request.name,
                scan_verdict=scan_result.verdict,
                risk=risk,
                profile=self.policy.name,
                matched_rule="tool.allow",
            )

        if self._matches(tool_name, self.policy.require_approval_tools):
            return GateDecision(
                allowed=False,
                reason=f"{request.name} requires approval because it matches the policy approval list.",
                tool_name=request.name,
                scan_verdict=scan_result.verdict,
                risk=risk,
                required_approval=True,
                profile=self.policy.name,
                matched_rule="tool.approval",
            )

        if scan_result.verdict == Verdict.SUSPICIOUS:
            if self._risk_at_least(risk, self.policy.block_risk_at_suspicious):
                return GateDecision(
                    allowed=False,
                    reason=(
                        f"Blocked {request.name}: {risk.value} risk tool under suspicious context."
                    ),
                    tool_name=request.name,
                    scan_verdict=scan_result.verdict,
                    risk=risk,
                    profile=self.policy.name,
                    matched_rule="risk.block_when_suspicious",
                )
            if self._risk_at_least(risk, self.policy.approval_risk_at_suspicious):
                return GateDecision(
                    allowed=False,
                    reason=(
                        f"{request.name} requires approval: {risk.value} risk tool under suspicious context."
                    ),
                    tool_name=request.name,
                    scan_verdict=scan_result.verdict,
                    risk=risk,
                    required_approval=True,
                    profile=self.policy.name,
                    matched_rule="risk.approval_when_suspicious",
                )

        if (
            scan_result.verdict == Verdict.SAFE
            and self.policy.approval_risk_at_safe is not None
            and self._risk_at_least(risk, self.policy.approval_risk_at_safe)
        ):
            return GateDecision(
                allowed=False,
                reason=f"{request.name} requires approval because it is {risk.value} risk.",
                tool_name=request.name,
                scan_verdict=scan_result.verdict,
                risk=risk,
                required_approval=True,
                profile=self.policy.name,
                matched_rule="risk.approval_when_safe",
            )

        return GateDecision(
            allowed=True,
            reason=f"Allowed {request.name}: {risk.value} risk under {scan_result.verdict.value} context.",
            tool_name=request.name,
            scan_verdict=scan_result.verdict,
            risk=risk,
            profile=self.policy.name,
        )

    def classify(self, request: ToolRequest) -> ToolRisk:
        if request.risk:
            try:
                return ToolRisk(request.risk.lower())
            except ValueError:
                pass

        tool_name = request.name.lower()
        if self._matches(tool_name, self.policy.critical_tools):
            return ToolRisk.CRITICAL
        if self._matches(tool_name, self.policy.high_risk_tools):
            return ToolRisk.HIGH
        if self._matches(tool_name, self.policy.medium_risk_tools):
            return ToolRisk.MEDIUM
        if self._has_write_like_args(request.args):
            return ToolRisk.MEDIUM
        return ToolRisk.LOW

    @staticmethod
    def _matches(tool_name: str, needles: tuple[str, ...]) -> bool:
        return any(needle in tool_name for needle in needles)

    @staticmethod
    def _risk_at_least(actual: ToolRisk, threshold: ToolRisk) -> bool:
        return RISK_ORDER[actual] >= RISK_ORDER[threshold]

    def _has_write_like_args(self, args: dict[str, Any]) -> bool:
        lowered_names = {name.lower() for name in args}
        return bool(lowered_names.intersection(self.policy.write_arg_names))


def get_policy_profile(name: str) -> ToolPolicy:
    try:
        return POLICY_PROFILES[name.lower()]
    except KeyError as exc:
        available = ", ".join(sorted(POLICY_PROFILES))
        raise ValueError(f"Unknown policy profile '{name}'. Available profiles: {available}.") from exc


def customize_policy(
    policy: ToolPolicy | str | None = None,
    *,
    name: str | None = None,
    allow_tools: tuple[str, ...] = (),
    deny_tools: tuple[str, ...] = (),
    require_approval_tools: tuple[str, ...] = (),
) -> ToolPolicy:
    base = get_policy_profile(policy) if isinstance(policy, str) else policy or get_policy_profile("balanced")
    return ToolPolicy(
        name=name or base.name,
        block_on_verdict=base.block_on_verdict,
        block_risk_at_suspicious=base.block_risk_at_suspicious,
        approval_risk_at_suspicious=base.approval_risk_at_suspicious,
        approval_risk_at_safe=base.approval_risk_at_safe,
        allow_tools=base.allow_tools + tuple(allow_tools),
        deny_tools=base.deny_tools + tuple(deny_tools),
        require_approval_tools=base.require_approval_tools + tuple(require_approval_tools),
        critical_tools=base.critical_tools,
        high_risk_tools=base.high_risk_tools,
        medium_risk_tools=base.medium_risk_tools,
        write_arg_names=base.write_arg_names,
    )
