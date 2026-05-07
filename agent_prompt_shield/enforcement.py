from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from .audit import AuditLog
from .models import EnforcementResult, ScanResult, ToolRequest
from .scanner import PromptShield
from .tool_gate import ToolGatekeeper, ToolPolicy


T = TypeVar("T")


class ToolEnforcer:
    """High-level guard used immediately before an agent executes a tool."""

    def __init__(
        self,
        shield: PromptShield | None = None,
        policy: ToolPolicy | str | None = None,
        audit_log: AuditLog | str | None = None,
    ) -> None:
        if shield is not None and policy is not None:
            raise ValueError("Pass either an existing shield or a policy, not both.")
        self.shield = shield or PromptShield(tool_gatekeeper=ToolGatekeeper(policy))
        self.audit_log = (
            audit_log
            if isinstance(audit_log, AuditLog)
            else AuditLog(audit_log)
            if audit_log
            else None
        )

    def enforce_text(
        self,
        *,
        untrusted_text: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        risk: str | None = None,
    ) -> EnforcementResult:
        scan = self.shield.scan(untrusted_text)
        return self.enforce_scan(
            scan,
            ToolRequest(name=tool_name, args=tool_args or {}, risk=risk),
        )

    def enforce_scan(self, scan: ScanResult, request: ToolRequest) -> EnforcementResult:
        decision = self.shield.gate_tool(request, scan)
        result = EnforcementResult(scan=scan, decision=decision)
        if self.audit_log:
            self.audit_log.record_enforcement(
                result,
                source="tool_enforcer",
                metadata={"tool_name": request.name, "tool_args": request.args},
            )
        return result

    def run_if_allowed(
        self,
        func: Callable[..., T],
        *,
        untrusted_text: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        risk: str | None = None,
    ) -> tuple[EnforcementResult, T | None]:
        result = self.enforce_text(
            untrusted_text=untrusted_text,
            tool_name=tool_name,
            tool_args=tool_args,
            risk=risk,
        )
        if not result.allowed:
            return result, None
        return result, func(**(tool_args or {}))
