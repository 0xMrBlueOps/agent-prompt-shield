# MCP Tool Output Proof

This proof shows the core runtime boundary: MCP and other tool outputs are data, not instructions.

Attack path:

1. An agent calls a read-only MCP-style search tool.
2. The returned text contains hidden instructions that ask the model to bypass approval.
3. The attacker tries to pivot that output into a high-impact public write such as `github.create_issue`.
4. Prompt Shield scans the untrusted tool output and gates the next tool call before execution.

Run:

```powershell
python examples/mcp_tool_output_gate_demo.py
```

Expected result:

```text
read-only MCP follow-up: ALLOWED -> notes found for: repository security notes
public GitHub write: BLOCKED -> verdict.blocked: Blocked github.create_issue because the context verdict is blocked.
```

The exact wording may change as policy messages improve, but the important property is stable: benign MCP output can continue to read-only work, while hostile MCP output blocks the GitHub write before execution.

Why this matters:

- MCP servers, browser pages, repository files, ticket text, and retrieval chunks can all become indirect prompt-injection carriers.
- A model-only defense asks the same compromised context to police itself.
- Prompt Shield puts a deterministic policy gate in front of tool execution, with scan findings and decision reasons available for audit.

This is not a sandbox. High-impact tools still need least privilege, human approval, credential isolation, and audit logging.

## X Draft

Do not post without approval.

```text
MCP output should be treated like hostile webpage text, not trusted agent instructions.

I added a small Prompt Shield proof:
- benign MCP search output can continue to read-only work
- hostile MCP output tries to create a public GitHub issue with secrets
- the GitHub write is blocked before execution

The fix is runtime policy before tools, not another prompt telling the model to be careful.
```
