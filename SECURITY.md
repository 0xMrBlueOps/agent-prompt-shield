# Security Policy

Agent Prompt Shield is an alpha, deterministic prompt-injection guardrail for
tool-using agents. It is not a complete security boundary and should be paired
with sandboxing, least privilege, human approval for risky tools, and audit
logging.

## Supported Versions

Security fixes are applied to the latest public release line.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1.0 | No |

## Responsible Disclosure

Please report security issues privately before publishing exploit details. This
includes bypasses that cause unsafe tool execution, missed prompt-injection
patterns, policy enforcement failures, sanitizer failures, audit-log integrity
issues, or packaging problems that affect downstream users.

Preferred contact:

- Email: tradingjp888@gmail.com
- GitHub Security Advisory: use the repository's private vulnerability reporting
  flow if it is enabled.

Please do not open a public issue with working exploit payloads until there has
been a reasonable private coordination window.

## Scope

In scope:

- Prompt-injection payloads that should be suspicious or blocked but are missed.
- Indirect prompt-injection payloads embedded in HTML, Markdown, logs, JSON,
  YAML, RAG snippets, memory entries, or tool output.
- Obfuscation techniques that bypass normalization or scanning.
- Tool policy failures, including incorrect allow/deny behavior, risk-level
  overrides, blocked context handling, and required human approval handling.
- Audit logging failures that omit meaningful enforcement evidence.
- CLI or packaging behavior that makes defensive use unreliable.

Out of scope:

- Claims that the project should detect every semantic, multimodal, encoded,
  memory-poisoning, or RAG-poisoning attack. These are documented limitations.
- Vulnerabilities in unrelated third-party tools or LLM providers.
- Social engineering reports with no concrete project behavior to reproduce.
- Denial-of-service reports that only rely on unrealistic local resource
  exhaustion without a practical defensive impact.

## Disclosure Process

1. Send a private report with reproduction details.
2. The maintainer will acknowledge the report when possible.
3. The report will be triaged as a detector bypass, enforcement bug, audit/logging
   bug, packaging issue, or documentation gap.
4. If accepted, a fix, test case, benchmark case, or documentation update will be
   prepared.
5. Public disclosure should wait until a fix or clear limitation note is
   available.

## Bypass Report Template

Use this structure when reporting a bypass:

````markdown
## Summary

Short description of the bypass or security issue.

## Affected Version

- agent-prompt-shield version:
- Python version:
- Install source: PyPI / GitHub / local checkout

## Payload

```text
Paste the smallest payload that reproduces the issue.
```

## Context

- Direct prompt injection / indirect prompt injection / RAG / memory / tool output / other:
- Trusted or untrusted source:
- Tool name and risk level, if relevant:
- Policy file or base profile, if relevant:

## Expected Behavior

What verdict, tool decision, sanitizer output, or audit event should have happened?

## Actual Behavior

What happened instead?

## Reproduction Steps

1. Command or code used to scan the payload.
2. Policy file or tool metadata used.
3. Observed result.

## Impact

Explain how this could lead to unsafe tool execution, data exposure, policy
bypass, missing audit evidence, or misleading security claims.

## Suggested Fix

Optional: normalization, rule, policy, sanitizer, audit, benchmark, or docs change.
````

## Security Model

See `SECURITY_MODEL.md` and `LIMITATIONS.md` for the full threat model,
non-goals, assumptions, and residual risks.
