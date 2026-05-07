# Agent Prompt Shield Limitations

Agent Prompt Shield is a deterministic guardrail for prompt-injection and tool-hijack risk. It can reduce exposure at important agent boundaries, but it cannot guarantee that an LLM agent is safe.

This document defines what the project does not claim to solve. It should be read alongside `SECURITY_MODEL.md`, `EVAL.md`, and the benchmark results.

## Core Non-Guarantee

A `safe` verdict means the current scanner did not match enough known-risk signals to classify the input as suspicious or blocked. It does not mean the input is harmless, semantically safe, or safe to combine with powerful tools.

Agent Prompt Shield does not provide:

- formal verification of agent behavior
- a sandbox
- model alignment
- complete prompt-injection prevention
- complete exfiltration prevention
- complete protection against malicious retrieved content
- complete protection against compromised tools, credentials, plugins, browsers, shells, memory stores, or vector databases

Use it as one control in a defense-in-depth agent system.

## False Negatives

False negatives are possible. The scanner may return `safe` for content that is actually malicious.

Likely false-negative classes include:

- novel attack phrasing not covered by the rule set
- attacks that depend on implied meaning rather than explicit keywords
- multi-turn attacks where each individual message looks benign
- split-payload attacks distributed across several documents, retrieval chunks, messages, or tool outputs
- attacks hidden in domain-specific language, code, logs, templates, or configuration files
- social-engineering instructions that sound like normal workflow guidance
- malicious content translated into languages or writing systems that the rules do not cover well

Because false negatives are unavoidable, a clean scan must not be used as permission to run high-impact tools without additional controls.

## False Positives

False positives are also expected. The scanner may classify benign content as `suspicious` or `blocked`.

Common false-positive pressure points include:

- security research discussing prompt-injection techniques
- documentation that quotes malicious examples for defensive purposes
- red-team reports, incident writeups, or benchmark corpora
- legitimate requests involving shells, credentials, logs, files, browsers, or cloud resources
- developer content that contains words such as "ignore", "system", "secret", "token", "execute", or "override" in benign contexts

False positives are a tradeoff of deterministic guardrails. Operators should tune policies, preserve audit logs, and review blocked cases rather than blindly weakening the rules.

## Semantic Attacks

The library does not understand intent the way a human reviewer does. It detects patterns and risk signals; it does not prove semantic meaning.

It may miss attacks that:

- never say "ignore previous instructions" or any obvious equivalent
- persuade the model through roleplay, authority, urgency, or emotional pressure
- embed malicious goals inside an otherwise legitimate task
- cause unsafe behavior through ambiguous instructions
- exploit model-specific reasoning failures
- depend on the agent's memory, previous actions, or hidden application state

Semantic safety must be handled by product design, least privilege, human approval, independent output validation, and monitoring.

## Encoded, Obfuscated, and Transformed Attacks

Agent Prompt Shield includes coverage for some encoded and obfuscated patterns, including hidden Markdown/HTML, Unicode smuggling, and base64-like payloads. That coverage is not complete.

It may miss content hidden through:

- uncommon encodings
- compression
- encryption
- fragmented base64
- homoglyphs outside the tested set
- zero-width or bidirectional Unicode combinations outside the tested set
- steganography
- image metadata
- nested document formats
- code-generated prompts
- transformations performed after scanning

Inputs should be normalized before scanning where possible. High-risk applications should scan both raw and decoded/extracted representations, then treat decoding failures as risk signals.

## Multimodal Attacks

The library operates on text. It does not inspect pixels, audio waveforms, video frames, OCR confidence, file structure, embedded objects, or multimodal model attention.

It cannot guarantee protection against:

- prompt injection written inside images
- hidden text revealed only through OCR
- adversarial screenshots or UI captures
- malicious audio instructions
- video-frame prompt injection
- PDF layout tricks that change reading order
- text hidden in document metadata or embedded files

If an agent consumes images, PDFs, audio, or video, the host application must extract text safely, preserve provenance, scan extracted content, and apply separate media-specific security controls.

## Memory Poisoning

Agent Prompt Shield can flag some explicit attempts to write malicious long-term memory, but it does not secure an agent's memory system.

It cannot guarantee that:

- malicious facts will never be stored
- stale or attacker-controlled memories will never influence future actions
- memory retrieval will preserve user intent
- memory writes are authorized
- memory records are correctly scoped to the right user, project, or trust level
- poisoned memory will be detected after it becomes part of trusted context

Memory systems need independent controls: write authorization, provenance tags, reviewable audit logs, scoped retrieval, deletion workflows, and periodic review of high-impact memories.

## RAG Poisoning and Vector Weaknesses

The library can scan retrieved text before prompt assembly, but it does not secure retrieval infrastructure.

It cannot guarantee protection against:

- poisoned documents in a corpus
- stale or unauthorized retrieval results
- embedding collisions or semantically misleading nearest neighbors
- cross-tenant retrieval leaks
- malicious chunks that look relevant to a benign query
- rank manipulation
- source spoofing
- partial-document retrieval that strips away safety context

RAG systems need document-level access control, source provenance, chunk-level trust labels, retrieval auditing, corpus hygiene, and post-retrieval scanning before content enters the agent context.

## Tool Safety

A clean scan does not make a tool call safe. Tool safety depends on the tool, its arguments, credentials, runtime environment, and blast radius.

Agent Prompt Shield cannot guarantee safety when:

- shell, filesystem, browser, network, email, GitHub, cloud, payment, calendar, or messaging tools are overprivileged
- credentials are exposed to the model or tool environment
- allow lists are too broad
- approval checks are missing or bypassable
- tool arguments are assembled after scanning
- a low-risk tool indirectly triggers a high-risk side effect
- tool outputs are trusted without rescanning

Every high-impact tool should be least-privileged, isolated, logged, and approval-gated.

## Required Companion Controls

Agent Prompt Shield should be paired with the following controls:

- sandboxing for code execution, browsers, file writes, and network access
- least-privilege credentials, scoped tokens, and per-tool permissions
- human approval for public, irreversible, financial, destructive, or privilege-expanding actions
- audit logging for scans, prompt assembly decisions, tool decisions, approvals, and tool outputs
- credential isolation so secrets are not visible to the model unless strictly necessary
- trusted/untrusted context separation in prompt construction
- output validation before acting on model-generated commands, URLs, paths, patches, or messages
- rate limits and cost controls for model calls and tools
- monitoring and incident review for blocked, suspicious, and unexpectedly allowed actions

Prompt Shield is strongest when it is treated as an early warning and policy-enforcement layer, not as the final security boundary.

## Research Status

This project is an alpha research and engineering artifact. Its benchmark corpora are useful for regression tracking and calibration, but they are not a representative sample of all live prompt-injection traffic.

Claims should remain narrow:

- deterministic detection of known prompt-injection and tool-hijack patterns
- auditable verdicts and tool-gating decisions
- reproducible regression tests
- explicit residual-risk documentation

Claims should not imply:

- complete prompt-injection defense
- production-grade agent security
- formal safety guarantees
- complete coverage of OWASP LLM risks
- protection against all semantic, encoded, multimodal, memory, or RAG attacks
