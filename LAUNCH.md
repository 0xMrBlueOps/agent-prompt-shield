# agent-prompt-shield v0.1.0 launch copy

Repo: https://github.com/0xMrBlueOps/agent-prompt-shield

PyPI package name decision: `agent-prompt-shield`

Reason: it matches the GitHub repo, the Python import remains `agent_prompt_shield`, and PyPI currently returns no project page for the exact package name.

## X post

Shipping v0.1.0 of agent-prompt-shield:

A small deterministic prompt-injection guardrail for tool-using agents.

- scans untrusted text before it enters agent context
- gates risky tool calls
- stdlib-only, no API dependency
- benchmark: 60/60 attacks caught, 0/100 benign false positives
- naive baseline comparison: 47/60 caught, 9/100 benign false positives
- includes 20 real-world-inspired cases derived from public prompt-injection research patterns
- alpha release: not a sandbox, not a complete security boundary

GitHub:
https://github.com/0xMrBlueOps/agent-prompt-shield

## Hacker News

Title:
Show HN: agent-prompt-shield - deterministic prompt-injection guardrail for agents

URL:
https://github.com/0xMrBlueOps/agent-prompt-shield

Optional first comment:
I built this because tool-using agents need a cheap local guard before untrusted text enters context or tool arguments execute.

The first release is intentionally simple: deterministic rules, no hosted API, no model dependency, stdlib-only, with a benchmark suite committed in the repo.

Fresh v0.1.0 benchmark:
- 60/60 prompt-injection attacks caught as suspicious or blocked
- 58/60 blocked outright
- 0/100 benign false positives
- naive keyword/regex baseline: 47/60 attacks caught, 9/100 benign false positives
- includes 20 rewritten, real-world-inspired cases derived from OWASP LLM01, indirect prompt injection research, InjecAgent, and Tensor Trust patterns

It is not a replacement for sandboxing or human approval. It is meant as a small, auditable layer for agent builders.

## Reddit: r/MachineLearning

Suggested format:
[D] I built a deterministic prompt-injection guardrail for tool-using agents

Post:
I released v0.1.0 of agent-prompt-shield, a small deterministic prompt-injection guardrail for tool-using agents:

https://github.com/0xMrBlueOps/agent-prompt-shield

The idea is to catch prompt-injection patterns before untrusted text enters an agent context or before risky tool arguments execute. It is stdlib-only, local, auditable, and intentionally not an LLM/API-based detector.

Fresh benchmark from the repo:
- 60/60 attacks caught as suspicious or blocked
- 58/60 blocked outright
- 0/100 benign false positives
- 20/20 real-world-inspired cases caught
- naive keyword/regex baseline caught 47/60 and flagged 9/100 benign prompts

The benchmark includes synthetic cases plus rewritten real-world-inspired cases derived from OWASP LLM01, indirect prompt injection research, InjecAgent, and Tensor Trust patterns. Categories include indirect injection, encoded payloads, markdown/HTML injection, context smuggling, tool hijack attempts, system prompt extraction, and multi-turn setup attacks.

I am looking for critique on the benchmark design, false-positive coverage, and whether deterministic guard layers like this are useful as a baseline alongside sandboxing and human approval.

## Discord short post

Shipped v0.1.0 of agent-prompt-shield:
https://github.com/0xMrBlueOps/agent-prompt-shield

It is a deterministic, stdlib-only prompt-injection guardrail for tool-using agents. It scans untrusted text before it enters context and can gate risky tool calls.

Fresh benchmark:
- 60/60 attacks caught
- 58/60 blocked
- 0/100 benign false positives
- naive baseline: 47/60 caught, 9/100 benign false positives
- 20 real-world-inspired cases derived from public research patterns

Looking for benchmark critique and real-world attack cases to add.
