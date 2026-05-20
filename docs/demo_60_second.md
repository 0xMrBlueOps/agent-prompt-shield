# 60-Second Demo: MCP Tool Output Cannot Authorize a Public Write

This demo proves one narrow runtime-control property:

> Untrusted MCP/tool output can suggest a risky public action, but it cannot authorize that action.

## Run It

From the repository root:

```powershell
python examples/mcp_tool_output_gate_demo.py
```

Expected output:

```text
read-only MCP follow-up: ALLOWED -> notes found for: repository security notes
public GitHub write: BLOCKED -> verdict.blocked: Blocked github.create_issue because the context verdict is blocked.
```

## What Happens

1. A benign MCP-style search result is added as untrusted context.
2. A read-only `notes.search` follow-up is allowed.
3. A hostile MCP-style result tries to bypass approval and create a public GitHub issue.
4. Prompt Shield blocks `github.create_issue` before the write tool executes.

## Why It Matters

Agents increasingly read untrusted webpages, tickets, repository files, documents, retrieval chunks, and MCP tool outputs. If that text can also authorize tool calls, prompt injection becomes a path to public writes, messages, shell commands, or data exposure.

Prompt Shield keeps the claim conservative: it does not make agents safe by itself. It adds a runtime gate so hostile context does not become authorization for high-impact tools.

## Copyable Claim

Prompt Shield is a lightweight runtime control layer for tool-using agents: scan untrusted context, keep trust boundaries explicit, and block risky tool calls when hostile context reaches a public or high-impact action.
