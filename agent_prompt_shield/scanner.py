from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Iterable

from .models import Finding, GateDecision, ScanResult, ToolRequest, Verdict
from .rules import DEFAULT_RULES, Rule
from .sanitizer import sanitize_untrusted_text
from .tool_gate import ToolGatekeeper


@dataclass(frozen=True)
class ScannerConfig:
    suspicious_threshold: int = 25
    blocked_threshold: int = 60
    canary_secrets: tuple[str, ...] = ()
    sanitize_on_suspicious: bool = True
    disabled_rules: tuple[str, ...] = ()
    disabled_categories: tuple[str, ...] = ()
    blocked_categories: tuple[str, ...] = ()
    rule_severity_overrides: Mapping[str, int] = field(default_factory=dict)
    category_severity_overrides: Mapping[str, int] = field(default_factory=dict)


class PromptShield:
    def __init__(
        self,
        rules: Iterable[Rule] = DEFAULT_RULES,
        config: ScannerConfig | None = None,
        tool_gatekeeper: ToolGatekeeper | None = None,
    ) -> None:
        self.rules = tuple(rules)
        self.config = config or ScannerConfig()
        self.tool_gatekeeper = tool_gatekeeper or ToolGatekeeper()

    def scan(self, text: str) -> ScanResult:
        findings = list(self._configured_findings(self._find_rule_matches(text)))
        findings.extend(self._find_canary_matches(text))
        score = min(100, sum(finding.severity for finding in findings))

        if self._has_blocked_category(findings) or score >= self.config.blocked_threshold:
            verdict = Verdict.BLOCKED
        elif score >= self.config.suspicious_threshold:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        sanitized = None
        if self.config.sanitize_on_suspicious and verdict != Verdict.SAFE:
            sanitized = sanitize_untrusted_text(text)

        return ScanResult(
            verdict=verdict,
            score=score,
            findings=tuple(sorted(findings, key=lambda item: (item.start, item.rule_id))),
            sanitized_text=sanitized,
        )

    def gate_tool(self, request: ToolRequest, scan_result: ScanResult) -> GateDecision:
        return self.tool_gatekeeper.evaluate(request, scan_result)

    def _find_rule_matches(self, text: str) -> Iterable[Finding]:
        for rule in self.rules:
            yield from rule.find(text)

    def _configured_findings(self, findings: Iterable[Finding]) -> Iterable[Finding]:
        disabled_rules = {rule.lower() for rule in self.config.disabled_rules}
        disabled_categories = {category.lower() for category in self.config.disabled_categories}

        for finding in findings:
            if finding.rule_id.lower() in disabled_rules:
                continue
            if finding.category.lower() in disabled_categories:
                continue

            severity = self.config.rule_severity_overrides.get(finding.rule_id)
            if severity is None:
                severity = self.config.category_severity_overrides.get(finding.category)
            if severity is not None:
                finding = replace(finding, severity=max(0, min(100, severity)))
            yield finding

    def _has_blocked_category(self, findings: Iterable[Finding]) -> bool:
        blocked_categories = {category.lower() for category in self.config.blocked_categories}
        if not blocked_categories:
            return False
        return any(finding.category.lower() in blocked_categories for finding in findings)

    def _find_canary_matches(self, text: str) -> Iterable[Finding]:
        lower_text = text.lower()
        for secret in self.config.canary_secrets:
            normalized = secret.strip()
            if not normalized:
                continue
            start = lower_text.find(normalized.lower())
            if start == -1:
                continue
            end = start + len(normalized)
            yield Finding(
                rule_id="canary.secret_seen",
                category="canary_secret",
                severity=60,
                message="Canary secret appeared in untrusted text.",
                evidence=normalized[:80],
                start=start,
                end=end,
            )
