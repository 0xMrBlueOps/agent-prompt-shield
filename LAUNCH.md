# agent-prompt-shield v0.1.2 launch copy

Repo: https://github.com/0xMrBlueOps/agent-prompt-shield

Release theme: MCP output is data, not authorization.

## X Post

Do not post without approval.

```text
Shipping agent-prompt-shield v0.1.2:

New proof: MCP tool output should be treated like hostile webpage text, not trusted agent instructions.

The demo shows:
- benign MCP output can continue to read-only work
- hostile MCP output tries to bypass approval
- a public GitHub write is blocked before execution

The narrow lesson:
untrusted text can suggest an action, but it should not authorize one.

Repo:
https://github.com/0xMrBlueOps/agent-prompt-shield
```

## GitHub Release Draft

Title:

```text
v0.1.2 - MCP tool-output gate proof
```

Body:

```text
This release adds a focused proof for MCP/tool-output prompt injection.

The core security property:

Untrusted tool output can suggest a public action, but it should not authorize one.

Added:
- examples/mcp_tool_output_gate_demo.py
- datasets/mcp_tool_output_injection.jsonl
- docs/mcp_tool_output_proof.md
- docs/portfolio_public_action_gate.md
- README proof section
- smoke-test coverage for the MCP demo

Verification:
- python examples/mcp_tool_output_gate_demo.py
- python -m unittest discover -s tests

Expected demo signal:
- read-only MCP follow-up: ALLOWED
- public GitHub write: BLOCKED

This is not a sandbox and does not make agents safe by itself. It is a small runtime control layer for reducing known prompt-injection and tool-hijack risk before high-impact tool execution.
```

## Hacker News / Reddit Draft

Do not post without approval.

```text
I added an MCP/tool-output injection proof to agent-prompt-shield.

The issue is that agents often treat tool results, docs, tickets, webpages, and MCP output as plain context. If that context contains instructions, it can try to pivot into a high-impact tool call: GitHub write, email, Slack, browser action, shell, etc.

The v0.1.2 demo keeps the claim narrow:
- benign MCP output can continue to read-only work
- hostile MCP output tries to bypass approval
- the public GitHub write is blocked before execution

The point is not "prompt filtering solves agents." It is that authorization should happen at the runtime/tool boundary, outside the compromised text stream.

Repo:
https://github.com/0xMrBlueOps/agent-prompt-shield
```

## Approval Boundary

No GitHub release, PyPI upload, X post, Hacker News post, Reddit post, Discord post, email, or outreach should be sent without Red's explicit approval.
