from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


class ToolRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: int
    message: str
    evidence: str
    start: int
    end: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
            "start": self.start,
            "end": self.end,
        }


@dataclass(frozen=True)
class ScanResult:
    verdict: Verdict
    score: int
    findings: tuple[Finding, ...] = ()
    sanitized_text: str | None = None

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCKED

    @property
    def suspicious(self) -> bool:
        return self.verdict in {Verdict.SUSPICIOUS, Verdict.BLOCKED}

    def reason_summary(self) -> str:
        if not self.findings:
            return "No prompt-injection indicators found."
        categories = sorted({finding.category for finding in self.findings})
        return f"{self.verdict.value} score={self.score}; categories={', '.join(categories)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "summary": self.reason_summary(),
            "findings": [finding.to_dict() for finding in self.findings],
            "sanitized_text": self.sanitized_text,
        }


@dataclass(frozen=True)
class ToolRequest:
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    risk: str | None = None
    context: str | None = None


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    tool_name: str
    scan_verdict: Verdict
    risk: ToolRisk = ToolRisk.LOW
    required_approval: bool = False
    profile: str = "balanced"
    matched_rule: str | None = None
    audit_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "tool_name": self.tool_name,
            "scan_verdict": self.scan_verdict.value,
            "risk": self.risk.value,
            "required_approval": self.required_approval,
            "profile": self.profile,
            "matched_rule": self.matched_rule,
            "audit_reason": self.audit_reason,
        }


@dataclass(frozen=True)
class EnforcementResult:
    scan: ScanResult
    decision: GateDecision

    @property
    def allowed(self) -> bool:
        return self.decision.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan": self.scan.to_dict(),
            "decision": self.decision.to_dict(),
        }
