# Changelog

## v0.1.2 MCP Tool-Output Gate

- Added an MCP-style tool-output injection proof showing that untrusted tool results can suggest public actions but should not authorize them.
- Added `examples/mcp_tool_output_gate_demo.py`, which allows a benign read-only follow-up and blocks a hostile `github.create_issue` write.
- Added `datasets/mcp_tool_output_injection.jsonl` as a regression fixture for tool-output-to-public-write attacks.
- Added `docs/mcp_tool_output_proof.md` and `docs/portfolio_public_action_gate.md` for conservative public/security framing.
- Updated README examples and smoke tests so the MCP proof is part of the release surface.

## v0.1.1 Research Alpha

- Added research-grade security framing, including `SECURITY_MODEL.md`, `LIMITATIONS.md`, `SECURITY.md`, and a lightweight research report.
- Added category-specific JSONL datasets, adversarial mutation testing, and benchmark regression checks.
- Added vulnerable/protected agent examples, attack walkthrough documentation, and JSONL audit-log behavior.
- Added stdlib-only YAML policy-as-code support for tool risk levels, allow/deny rules, approval requirements, blocked contexts, and audit reasons.
- Added GitHub Actions and local release gates for tests, Ruff, mypy, Bandit, `pip-audit .`, benchmark regression, package build, and `twine check`.

## v0.1.0

- Initial alpha release of Agent Prompt Shield.
