from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar, cast

from .context import ShieldedContext
from .models import EnforcementResult
from .scanner import PromptShield
from .tool_gate import ToolGatekeeper

T = TypeVar("T")


class ToolBlockedError(RuntimeError):
    """Raised when a guarded adapter refuses to execute a tool."""

    def __init__(self, result: EnforcementResult) -> None:
        super().__init__(result.decision.reason)
        self.result = result


@dataclass(frozen=True)
class ToolExecution:
    result: EnforcementResult
    output: Any = None

    @property
    def allowed(self) -> bool:
        return self.result.allowed


class AgentGuard:
    """Dependency-free adapter for wrapping an agent's context and tool calls."""

    def __init__(
        self,
        *,
        policy: str | None = None,
        audit_log: str | None = None,
        raise_on_block: bool = False,
    ) -> None:
        shield = PromptShield(tool_gatekeeper=ToolGatekeeper(policy))
        self.context = ShieldedContext(shield=shield, audit_log=audit_log)
        self.raise_on_block = raise_on_block

    def add_system(self, text: str, *, source: str = "system") -> None:
        self.context.add_trusted(text, source=source)

    def add_untrusted(self, text: str, *, source: str = "untrusted") -> None:
        self.context.add_untrusted(text, source=source)

    def prompt_context(self) -> str:
        return self.context.build_prompt_context()

    def check_tool(
        self,
        tool_name: str,
        *,
        tool_args: dict[str, Any] | None = None,
        risk: str | None = None,
    ) -> EnforcementResult:
        return self.context.enforce_tool(
            tool_name=tool_name,
            tool_args=tool_args or {},
            risk=risk,
        )

    def run_tool(
        self,
        tool: Callable[..., T],
        *,
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        risk: str | None = None,
    ) -> ToolExecution:
        args = tool_args or {}
        name = cast(str, tool_name or getattr(tool, "__name__", "tool"))
        result = self.check_tool(name, tool_args=args, risk=risk)
        if not result.allowed:
            if self.raise_on_block:
                raise ToolBlockedError(result)
            return ToolExecution(result=result)
        return ToolExecution(result=result, output=tool(**args))

    def wrap_tool(
        self,
        tool: Callable[..., T],
        *,
        tool_name: str | None = None,
        risk: str | None = None,
    ) -> Callable[..., T]:
        name = tool_name or getattr(tool, "__name__", "tool")

        def guarded_tool(**kwargs: Any) -> T:
            execution = self.run_tool(
                tool,
                tool_name=name,
                tool_args=kwargs,
                risk=risk,
            )
            if not execution.allowed:
                raise ToolBlockedError(execution.result)
            return cast(T, execution.output)

        return guarded_tool

    def openai_tool_call(
        self,
        tool_call: dict[str, Any],
        tools: dict[str, Callable[..., T]],
        *,
        risk: str | None = None,
    ) -> ToolExecution:
        name, args = parse_openai_tool_call(tool_call)
        try:
            tool = tools[name]
        except KeyError as exc:
            raise KeyError(f"No registered tool named '{name}'.") from exc
        return self.run_tool(tool, tool_name=name, tool_args=args, risk=risk)


def parse_openai_tool_call(tool_call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Extract a function name and JSON args from an OpenAI-style tool call."""

    function = tool_call.get("function", {})
    name = function.get("name") or tool_call.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("OpenAI tool call is missing function.name.")

    raw_args = function.get("arguments", tool_call.get("arguments", {}))
    if raw_args in (None, ""):
        return name, {}
    if isinstance(raw_args, dict):
        return name, raw_args
    if isinstance(raw_args, str):
        parsed = json.loads(raw_args)
        if not isinstance(parsed, dict):
            raise ValueError("OpenAI tool call arguments must decode to an object.")
        return name, parsed
    raise ValueError("OpenAI tool call arguments must be a JSON string or dict.")


def wrap_langchain_callable(
    tool: Callable[..., T],
    guard: AgentGuard,
    *,
    tool_name: str | None = None,
    risk: str | None = None,
) -> Callable[..., T]:
    """Return a callable compatible with simple LangChain-style tool wrappers."""

    return guard.wrap_tool(tool, tool_name=tool_name, risk=risk)
