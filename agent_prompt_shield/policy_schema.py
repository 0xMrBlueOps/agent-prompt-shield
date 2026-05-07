from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import ToolRisk

VALID_BASE_PROFILES = {"strict", "balanced", "permissive"}
VALID_AUDIT_RULES = {
    "context.blocked",
    "tool.deny",
    "tool.allow",
    "tool.approval",
    "verdict.blocked",
    "risk.block_when_suspicious",
    "risk.approval_when_suspicious",
    "risk.approval_when_safe",
}


@dataclass(frozen=True)
class PolicyDocument:
    name: str
    base_profile: str = "balanced"
    tool_risk_levels: dict[str, ToolRisk] = field(default_factory=dict)
    allow_tools: tuple[str, ...] = ()
    deny_tools: tuple[str, ...] = ()
    require_approval_tools: tuple[str, ...] = ()
    blocked_contexts: tuple[str, ...] = ()
    audit_reasons: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> PolicyDocument:
        if not isinstance(raw, dict):
            raise PolicySchemaError("Policy must be a YAML mapping.")

        name = _required_string(raw, "name")
        base_profile = _optional_string(raw, "base_profile", "balanced").lower()
        if base_profile not in VALID_BASE_PROFILES:
            raise PolicySchemaError(
                f"base_profile must be one of: {', '.join(sorted(VALID_BASE_PROFILES))}."
            )

        tool_risk_levels = _risk_mapping(raw.get("tool_risk_levels", {}), "tool_risk_levels")
        audit_reasons = _string_mapping(raw.get("audit_reasons", {}), "audit_reasons")
        invalid_audit_rules = set(audit_reasons) - VALID_AUDIT_RULES
        if invalid_audit_rules:
            invalid = ", ".join(sorted(invalid_audit_rules))
            valid = ", ".join(sorted(VALID_AUDIT_RULES))
            raise PolicySchemaError(f"Unknown audit reason key(s): {invalid}. Valid keys: {valid}.")

        return cls(
            name=name,
            base_profile=base_profile,
            tool_risk_levels=tool_risk_levels,
            allow_tools=_string_list(raw.get("allow_tools", ()), "allow_tools"),
            deny_tools=_string_list(raw.get("deny_tools", ()), "deny_tools"),
            require_approval_tools=_string_list(
                raw.get("require_approval_tools", ()), "require_approval_tools"
            ),
            blocked_contexts=_string_list(raw.get("blocked_contexts", ()), "blocked_contexts"),
            audit_reasons=audit_reasons,
        )


class PolicySchemaError(ValueError):
    pass


def _required_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PolicySchemaError(f"{key} must be a non-empty string.")
    return value.strip()


def _optional_string(raw: dict[str, Any], key: str, default: str) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise PolicySchemaError(f"{key} must be a non-empty string.")
    return value.strip()


def _string_list(value: Any, key: str) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, list):
        raise PolicySchemaError(f"{key} must be a YAML list of strings.")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PolicySchemaError(f"{key} entries must be non-empty strings.")
        items.append(item.strip())
    return tuple(items)


def _string_mapping(value: Any, key: str) -> dict[str, str]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise PolicySchemaError(f"{key} must be a YAML mapping.")
    output: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise PolicySchemaError(f"{key} keys must be non-empty strings.")
        if not isinstance(raw_value, str) or not raw_value.strip():
            raise PolicySchemaError(f"{key} values must be non-empty strings.")
        output[raw_key.strip()] = raw_value.strip()
    return output


def _risk_mapping(value: Any, key: str) -> dict[str, ToolRisk]:
    raw_mapping = _string_mapping(value, key)
    output: dict[str, ToolRisk] = {}
    for tool_match, raw_risk in raw_mapping.items():
        try:
            output[tool_match] = ToolRisk(raw_risk.lower())
        except ValueError as exc:
            valid = ", ".join(risk.value for risk in ToolRisk)
            raise PolicySchemaError(
                f"{key}.{tool_match} must be one of: {valid}."
            ) from exc
    return output
