from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .audit import AuditLog
from .models import EnforcementResult, ScanResult, ToolRequest, Verdict
from .scanner import PromptShield


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class ContextEntry:
    text: str
    source: str = "unknown"
    trust: TrustLevel = TrustLevel.UNTRUSTED
    scan: ScanResult | None = None

    @property
    def prompt_text(self) -> str:
        if self.trust == TrustLevel.TRUSTED:
            return self.text
        if self.scan and self.scan.sanitized_text:
            return self.scan.sanitized_text
        return self.text

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "trust": self.trust.value,
            "text": self.text,
            "prompt_text": self.prompt_text,
            "scan": self.scan.to_dict() if self.scan else None,
        }


@dataclass(frozen=True)
class ContextReport:
    verdict: Verdict
    score: int
    entries: tuple[ContextEntry, ...] = field(default_factory=tuple)

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCKED

    @property
    def suspicious(self) -> bool:
        return self.verdict in {Verdict.SUSPICIOUS, Verdict.BLOCKED}

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "entries": [entry.to_dict() for entry in self.entries],
        }


class ShieldedContext:
    """Tracks mixed-trust context before it is handed to an agent prompt."""

    def __init__(
        self,
        shield: PromptShield | None = None,
        audit_log: AuditLog | str | None = None,
    ) -> None:
        self.shield = shield or PromptShield()
        self.audit_log = (
            audit_log
            if isinstance(audit_log, AuditLog)
            else AuditLog(audit_log)
            if audit_log
            else None
        )
        self._entries: list[ContextEntry] = []

    @property
    def entries(self) -> tuple[ContextEntry, ...]:
        return tuple(self._entries)

    def add_trusted(self, text: str, *, source: str = "trusted") -> ContextEntry:
        entry = ContextEntry(text=text, source=source, trust=TrustLevel.TRUSTED)
        self._entries.append(entry)
        return entry

    def add_untrusted(self, text: str, *, source: str = "untrusted") -> ContextEntry:
        scan = self.shield.scan(text)
        entry = ContextEntry(text=text, source=source, trust=TrustLevel.UNTRUSTED, scan=scan)
        self._entries.append(entry)
        if self.audit_log:
            self.audit_log.record_scan(
                scan,
                source=source,
                metadata={"trust": TrustLevel.UNTRUSTED.value},
            )
        return entry

    def report(self) -> ContextReport:
        scans = [entry.scan for entry in self._entries if entry.scan is not None]
        score = min(100, sum(scan.score for scan in scans))
        verdict = Verdict.SAFE
        if any(scan.verdict == Verdict.BLOCKED for scan in scans):
            verdict = Verdict.BLOCKED
        elif any(scan.verdict == Verdict.SUSPICIOUS for scan in scans):
            verdict = Verdict.SUSPICIOUS
        return ContextReport(verdict=verdict, score=score, entries=self.entries)

    def build_prompt_context(self) -> str:
        lines: list[str] = []
        for entry in self._entries:
            lines.append(f"[{entry.trust.value}:{entry.source}]")
            lines.append(entry.prompt_text)
        return "\n\n".join(lines)

    def enforce_tool(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        risk: str | None = None,
        context: str | None = None,
    ) -> EnforcementResult:
        synthetic_scan = self._combined_scan()
        request = ToolRequest(name=tool_name, args=tool_args or {}, risk=risk, context=context)
        decision = self.shield.gate_tool(request, synthetic_scan)
        result = EnforcementResult(scan=synthetic_scan, decision=decision)
        if self.audit_log:
            self.audit_log.record_enforcement(
                result,
                source="shielded_context",
                metadata={"tool_name": tool_name, "tool_args": tool_args or {}},
            )
        return result

    def _combined_scan(self) -> ScanResult:
        findings = tuple(
            finding
            for entry in self._entries
            if entry.scan is not None
            for finding in entry.scan.findings
        )
        report = self.report()
        sanitized = self.build_prompt_context() if report.suspicious else None
        return ScanResult(
            verdict=report.verdict,
            score=report.score,
            findings=findings,
            sanitized_text=sanitized,
        )
