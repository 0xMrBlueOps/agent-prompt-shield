from __future__ import annotations

from pathlib import Path
from typing import Any

from .policy_schema import PolicyDocument, PolicySchemaError
from .tool_gate import ToolPolicy, get_policy_profile


class PolicyParseError(ValueError):
    pass


def load_policy_file(path: str | Path) -> ToolPolicy:
    """Load a policy-as-code YAML file into a ToolPolicy."""

    document = load_policy_document(path)
    base = get_policy_profile(document.base_profile)
    return ToolPolicy(
        name=document.name,
        block_on_verdict=base.block_on_verdict,
        block_risk_at_suspicious=base.block_risk_at_suspicious,
        approval_risk_at_suspicious=base.approval_risk_at_suspicious,
        approval_risk_at_safe=base.approval_risk_at_safe,
        allow_tools=base.allow_tools + document.allow_tools,
        deny_tools=base.deny_tools + document.deny_tools,
        require_approval_tools=base.require_approval_tools + document.require_approval_tools,
        critical_tools=base.critical_tools,
        high_risk_tools=base.high_risk_tools,
        medium_risk_tools=base.medium_risk_tools,
        write_arg_names=base.write_arg_names,
        tool_risk_levels=document.tool_risk_levels,
        blocked_contexts=document.blocked_contexts,
        audit_reasons=document.audit_reasons,
    )


def load_policy_document(path: str | Path) -> PolicyDocument:
    raw_text = Path(path).read_text(encoding="utf-8")
    try:
        raw_mapping = parse_policy_yaml(raw_text)
        return PolicyDocument.from_mapping(raw_mapping)
    except (PolicyParseError, PolicySchemaError):
        raise
    except Exception as exc:
        raise PolicyParseError(f"Failed to load policy YAML: {exc}") from exc


def parse_policy_yaml(text: str) -> dict[str, Any]:
    """Parse the small YAML subset used by Prompt Shield policy files.

    The parser intentionally supports only mappings, scalar strings, and scalar
    lists. That keeps the package stdlib-only while still allowing readable
    policy-as-code files.
    """

    lines = _logical_lines(text)
    if not lines:
        raise PolicyParseError("Policy YAML is empty.")
    root, index = _parse_mapping(lines, 0, lines[0][0])
    if index != len(lines):
        raise PolicyParseError(f"Unexpected YAML content near line {lines[index][2]}.")
    return root


def _logical_lines(text: str) -> list[tuple[int, str, int]]:
    output: list[tuple[int, str, int]] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if "\t" in raw_line:
            raise PolicyParseError(f"Tabs are not supported in policy YAML at line {lineno}.")
        indent = len(line) - len(line.lstrip(" "))
        output.append((indent, line.strip(), lineno))
    return output


def _parse_mapping(
    lines: list[tuple[int, str, int]],
    index: int,
    indent: int,
) -> tuple[dict[str, Any], int]:
    output: dict[str, Any] = {}
    while index < len(lines):
        current_indent, content, lineno = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise PolicyParseError(f"Unexpected indentation at line {lineno}.")
        if content.startswith("- "):
            raise PolicyParseError(f"Expected mapping key at line {lineno}.")
        if ":" not in content:
            raise PolicyParseError(f"Expected key: value at line {lineno}.")
        key, raw_value = content.split(":", 1)
        key = key.strip()
        if not key:
            raise PolicyParseError(f"Empty mapping key at line {lineno}.")
        raw_value = raw_value.strip()
        if raw_value:
            output[key] = _parse_scalar(raw_value)
            index += 1
            continue
        if index + 1 >= len(lines) or lines[index + 1][0] <= current_indent:
            output[key] = {}
            index += 1
            continue
        next_indent, next_content, _ = lines[index + 1]
        if next_content.startswith("- "):
            output[key], index = _parse_list(lines, index + 1, next_indent)
        else:
            output[key], index = _parse_mapping(lines, index + 1, next_indent)
    return output, index


def _parse_list(
    lines: list[tuple[int, str, int]],
    index: int,
    indent: int,
) -> tuple[list[Any], int]:
    output: list[Any] = []
    while index < len(lines):
        current_indent, content, lineno = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise PolicyParseError(f"Nested list values are not supported at line {lineno}.")
        if not content.startswith("- "):
            break
        raw_value = content[2:].strip()
        if not raw_value:
            raise PolicyParseError(f"Empty list values are not supported at line {lineno}.")
        output.append(_parse_scalar(raw_value))
        index += 1
    return output, index


def _parse_scalar(raw_value: str) -> str:
    if (
        len(raw_value) >= 2
        and raw_value[0] == raw_value[-1]
        and raw_value[0] in {"'", '"'}
    ):
        return raw_value[1:-1]
    return raw_value
