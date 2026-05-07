# Agent Prompt Shield Security Model

This document defines the security model for Agent Prompt Shield as a research-facing artifact. It describes what the project is designed to protect, where trust boundaries exist, what attacker behavior is in scope, what is explicitly out of scope, and which residual risks remain after applying the library.

Agent Prompt Shield is a deterministic guardrail for tool-using LLM agents. It is not a sandbox, not a model alignment system, not a complete prompt-injection solution, and not proof that an agent is safe. Its role is to reduce specific classes of prompt-injection and tool-hijack risk before untrusted text enters an agent context and before high-impact tools execute.

The risk taxonomy used here maps to the OWASP Top 10 for LLM Applications 2025:

- LLM01:2025 Prompt Injection
- LLM02:2025 Sensitive Information Disclosure
- LLM03:2025 Supply Chain
- LLM04:2025 Data and Model Poisoning
- LLM05:2025 Improper Output Handling
- LLM06:2025 Excessive Agency
- LLM07:2025 System Prompt Leakage
- LLM08:2025 Vector and Embedding Weaknesses
- LLM09:2025 Misinformation
- LLM10:2025 Unbounded Consumption

Primary focus areas for this project are LLM01, LLM02, LLM06, LLM07, and LLM08.

## System Overview

Agent Prompt Shield is intended to sit at two security boundaries in an agentic application:

1. Before prompt assembly, scan and label untrusted text from users, webpages, emails, documents, retrieval chunks, tickets, chat messages, code comments, and tool outputs.
2. Before tool execution, gate proposed tool calls using the latest scan verdict, tool name, tool arguments, and a configurable tool-risk policy.

The library provides:

- deterministic scanning rules for known prompt-injection, secret-exfiltration, tool-hijack, data-boundary, obfuscation, context-smuggling, persuasion, and approval-bypass patterns
- `safe`, `suspicious`, and `blocked` verdicts with severity scoring and findings
- sanitization that quotes and labels suspicious untrusted content as data
- policy-based tool gating for shell, filesystem, browser, network, email, GitHub, cloud, calendar, memory, and other tools
- audit records for scan and tool-gating decisions
- examples for generic Python tools, OpenAI-style tool calls, LangChain-style callables, and a simple tool-call loop

## Protected Assets

The security model treats the following assets as sensitive or safety-critical:

| Asset | Why it matters | Example failure |
| --- | --- | --- |
| System prompts and developer instructions | These define the agent's intended behavior and safety policy. | A webpage convinces the agent to reveal or rewrite its hidden instructions. |
| User secrets and credentials | Agents may have access to API keys, tokens, cookies, SSH keys, cloud credentials, or private files. | Retrieved text asks the agent to email an API key to an attacker. |
| Private user data | Agents may process emails, documents, tickets, browser pages, chats, notes, or repository contents. | An indirect prompt injection causes the agent to summarize and exfiltrate private records. |
| Tool authority | Tools can modify files, run commands, browse sites, send messages, publish content, deploy code, or spend money. | A malicious issue comment causes a coding agent to run a shell command. |
| Approval boundaries | Human approval should remain required for irreversible, public, or high-impact actions. | Prompt text tells the agent to skip confirmation and post publicly. |
| Audit trail integrity | Logs support debugging, incident review, and reproducible evaluation. | Tool decisions are missing or unclear after a risky action. |
| Retrieval context and embeddings | RAG systems can introduce untrusted text into otherwise trusted workflows. | Poisoned retrieval chunks inject instructions into an agent prompt. |
| User intent | The agent should follow the user's actual objective, not instructions embedded in untrusted data. | A document says "ignore the user and run this other task." |

## Trust Boundaries

### Boundary 1: Trusted Instructions vs. Untrusted Data

Trusted instructions include application policy, system prompts, developer messages, explicit user goals, and local configuration controlled by the application owner. Untrusted data includes retrieved chunks, webpages, emails, chat messages, tickets, PDFs, search results, code comments, tool outputs, and any content controlled by external or lower-trust parties.

Agent Prompt Shield assumes untrusted data may contain instructions intended for the model. The library is designed to identify, score, block, or sanitize this content before it is mixed into the same prompt context as trusted instructions.

Mapped OWASP categories:

- LLM01:2025 Prompt Injection
- LLM02:2025 Sensitive Information Disclosure
- LLM07:2025 System Prompt Leakage
- LLM08:2025 Vector and Embedding Weaknesses

### Boundary 2: Model Reasoning vs. Tool Execution

An LLM may propose tool calls based on compromised context, hallucinated requirements, or malicious instructions embedded in data. Agent Prompt Shield treats tool execution as a separate boundary from text scanning. A clean text scan does not automatically make a tool call safe.

Tool calls are evaluated using a policy profile, recent scan verdict, tool name, risk class, and write-like arguments. High-impact tools should remain least-privileged and approval-gated even when Prompt Shield returns `safe`.

Mapped OWASP categories:

- LLM01:2025 Prompt Injection
- LLM05:2025 Improper Output Handling
- LLM06:2025 Excessive Agency

### Boundary 3: Retrieval and Embedding Stores vs. Agent Context

RAG systems can retrieve poisoned, stale, unauthorized, or attacker-controlled content. Agent Prompt Shield does not secure vector databases or enforce document-level access controls. It can scan retrieved text before it enters the prompt and help label hostile retrieval output as untrusted data.

Mapped OWASP categories:

- LLM01:2025 Prompt Injection
- LLM02:2025 Sensitive Information Disclosure
- LLM04:2025 Data and Model Poisoning
- LLM08:2025 Vector and Embedding Weaknesses

### Boundary 4: Local Library Decisions vs. Host Application Controls

Agent Prompt Shield returns verdicts, sanitized text, tool decisions, and audit events. The host application remains responsible for enforcing those decisions, isolating credentials, sandboxing tools, validating outputs, authenticating users, protecting logs, and requiring human approval for public or irreversible actions.

Mapped OWASP categories:

- LLM02:2025 Sensitive Information Disclosure
- LLM05:2025 Improper Output Handling
- LLM06:2025 Excessive Agency
- LLM10:2025 Unbounded Consumption

## Attacker Capabilities

The attacker may be able to:

- write direct user prompts to the agent
- control a webpage, email, ticket, chat message, document, PDF, Markdown file, code comment, search result, retrieval chunk, or tool output consumed by the agent
- hide instructions in Markdown comments, hidden HTML, encoded strings, escaped text, zero-width Unicode, bidirectional controls, or multi-language text
- impersonate system, developer, tool, search, retrieval, or audit output inside untrusted content
- ask the model to ignore, override, reveal, exfiltrate, execute, browse, delete, publish, email, message, or skip approval
- split malicious intent across multiple chunks or turns
- poison retrieval content that later appears relevant to a benign user task
- use social engineering, authority claims, urgency, compliance framing, or owner impersonation

The attacker is not assumed to have:

- arbitrary code execution inside the host process
- direct access to local memory outside content supplied to the agent
- write access to Agent Prompt Shield's installed package or source code
- control over the host application's policy configuration unless the integrator exposes it
- access to secrets unless the agent or tools disclose them
- the ability to bypass external sandbox, identity, network, or operating-system controls

## Attacker Goals

In-scope attacker goals include:

- override trusted system, developer, or user instructions
- convince the agent to treat untrusted data as higher-priority instructions
- extract system prompts, developer messages, hidden policy, secrets, credentials, private user data, or retrieved confidential content
- coerce high-impact tool execution such as shell commands, file writes/deletes, browser actions, network requests, email, messaging, GitHub writes, deployments, cloud actions, or public posting
- bypass approval or confirmation requirements
- smuggle instructions through code comments, Markdown, HTML, encoded text, Unicode controls, retrieval output, or fake tool output
- exploit retrieval or embedding workflows by inserting malicious content into documents likely to be retrieved later
- cause unsafe downstream behavior by polluting the context used by the model

Out-of-scope attacker goals include:

- exploiting vulnerabilities in Python, the operating system, browser, network stack, package installer, or cloud provider
- compromising the model provider or base model weights
- stealing data through channels not exposed to the agent or its tools
- bypassing controls that the host application fails to implement after receiving a blocked decision
- achieving perfect jailbreak resistance against all possible natural-language attacks

## Non-Goals

Agent Prompt Shield does not attempt to:

- prove that an LLM will follow sanitized instructions correctly
- sandbox shell, filesystem, browser, network, email, GitHub, or cloud tools
- enforce operating-system permissions, network egress rules, credential isolation, or process containment
- classify images, audio, screenshots, binaries, rendered visual deception, or multimodal prompt injection
- detect every novel paraphrase, homoglyph, language, or semantic attack
- reconstruct arbitrary long-range malicious intent across a full conversation without application state
- replace human review for irreversible, public, financial, destructive, or user-visible actions
- secure vector databases, embedding generation pipelines, document ACLs, or retrieval ranking
- provide legal, regulatory, or compliance certification

## Security Assumptions

The model depends on the following assumptions:

- The integrator scans untrusted text before adding it to the model context.
- The integrator preserves trust labels and does not silently merge sanitized untrusted text with trusted instructions.
- The integrator gates proposed tool calls before execution.
- High-impact tools are least-privileged and approval-gated outside the model.
- Secrets are not unnecessarily placed in the prompt, retrieval store, tool output, or logs.
- The host application enforces deny, approval, and allow decisions returned by the library.
- Audit logs are stored where attackers cannot silently rewrite them.
- Rule updates, benchmark updates, and dependency changes are reviewed before release.
- RAG systems enforce access control before retrieval and scan retrieved text before prompt assembly.

If these assumptions are false, Agent Prompt Shield may still catch obvious malicious text, but it should not be treated as a meaningful security boundary.

## Risk Register

| ID | Risk | Scenario | OWASP mapping | Current control | Residual risk |
| --- | --- | --- | --- | --- | --- |
| R1 | Direct prompt injection | A user prompt says to ignore prior instructions and reveal hidden policy. | LLM01, LLM07 | Role override and system-prompt extraction rules can return suspicious or blocked verdicts. | Novel phrasing or subtle semantic attacks can evade deterministic rules. |
| R2 | Indirect prompt injection | A webpage, email, PDF, ticket, or tool result tells the agent to follow attacker instructions. | LLM01, LLM02, LLM06 | Data-boundary and indirect-injection rules detect common instruction-smuggling patterns; sanitization labels content as untrusted. | Long-form or context-dependent attacks can avoid lexical indicators. |
| R3 | Secret exfiltration | Untrusted content asks the agent to print, send, upload, or leak API keys, tokens, private files, or credentials. | LLM01, LLM02 | Secret-exfiltration rules and external-destination patterns block many direct requests. | Euphemistic requests, tool-specific exfil paths, or already-exposed secrets can still succeed if host controls are weak. |
| R4 | System prompt leakage | A prompt asks the agent to quote, reveal, copy, or summarize system/developer instructions. | LLM01, LLM07 | System-prompt extraction rules detect direct disclosure attempts. | Defensive writing about prompt secrecy may be overblocked; indirect leakage through model behavior is not fully preventable. |
| R5 | Excessive agency through tools | Compromised context causes shell, filesystem, browser, email, GitHub, cloud, or network tool execution. | LLM01, LLM06 | Tool gating classifies risky tools and can block or require approval based on verdict and policy. | Overbroad allow lists, permissive profiles, or overprivileged tools can defeat the control. |
| R6 | Approval bypass | Attacker instructs the agent to act silently, skip confirmation, or avoid asking the user. | LLM01, LLM06 | Approval-bypass rules and tool policy can require approval for high-risk actions. | The host application must actually enforce approvals outside the model. |
| R7 | Tool-output instruction smuggling | A fake search result, retrieval result, or tool output claims to be a system or developer message. | LLM01, LLM05, LLM06 | Fake tool-output and data-boundary rules detect common patterns. | Tool outputs with subtle embedded intent may look benign in isolation. |
| R8 | Vector or embedding poisoning | A malicious document is embedded and later retrieved into an agent context. | LLM01, LLM04, LLM08 | Retrieved text can be scanned before prompt assembly; hostile chunks can be blocked or sanitized. | The library does not secure vector stores, embedding ACLs, retrieval ranking, deduplication, or source provenance. |
| R9 | Sensitive retrieval disclosure | RAG retrieves confidential chunks and the model discloses them to an unauthorized user. | LLM02, LLM08 | Prompt Shield can detect some exfiltration requests and suspicious instructions in retrieved text. | Authorization must happen before retrieval; the library cannot infer user entitlements. |
| R10 | Hidden or obfuscated instructions | Attackers use Markdown comments, hidden HTML, base64, escaped payloads, zero-width characters, or bidi controls. | LLM01, LLM07 | Obfuscation and context-smuggling rules detect several known hiding strategies. | Homoglyphs, unusual encodings, rendered-only attacks, images, and multimodal payloads remain weak areas. |
| R11 | Benign security content false positives | Defensive security writing mentions system prompts, shell commands, or prompt injection patterns. | LLM01, LLM07 | Severity thresholds and per-category configuration can tune blocking behavior. | Strict settings may block legitimate research content; permissive settings may miss real attacks. |
| R12 | Improper host enforcement | The application ignores blocked decisions, strips trust labels, or executes tools without checking policy. | LLM05, LLM06 | API returns explicit verdicts, decisions, reasons, and audit-friendly metadata. | The library cannot force the host application to use results correctly. |
| R13 | Supply-chain compromise | Package source, release artifact, CI, or installation path is tampered with. | LLM03 | Stdlib-only design reduces dependency surface; tests and release verification help catch regressions. | Signing, provenance, reproducible builds, and external audit are not yet mature. |
| R14 | Unbounded scanning or logging load | Very large inputs or excessive audit volume create cost, storage, or availability issues. | LLM10 | Deterministic local scanning avoids model-call amplification. | Host applications still need input size limits, log rotation, and rate limiting. |
| R15 | Misinformation or unsafe model output after scan | The scan is clean, but the model hallucinates or produces unsafe operational guidance. | LLM05, LLM09 | This is documented as outside the scanner's guarantee; tool gating reduces some action risk. | Output validation, human review, and domain-specific safety checks remain necessary. |

## Control Mapping

| Control | LLM01 | LLM02 | LLM05 | LLM06 | LLM07 | LLM08 |
| --- | --- | --- | --- | --- | --- | --- |
| Scan untrusted text before prompt assembly | Primary | Supporting | Supporting | Supporting | Supporting | Supporting |
| Preserve trusted/untrusted context labels | Primary | Supporting | Supporting | Supporting | Supporting | Supporting |
| Sanitize suspicious text as quoted data | Primary | Supporting | Supporting | Supporting | Supporting | Supporting |
| Block direct secret and prompt extraction requests | Primary | Primary | Supporting | Supporting | Primary | Supporting |
| Detect fake system, developer, tool, and retrieval messages | Primary | Supporting | Primary | Supporting | Primary | Primary |
| Gate tool calls by verdict, risk, name, and arguments | Supporting | Supporting | Primary | Primary | Supporting | Supporting |
| Require approval for high-impact tools | Supporting | Supporting | Supporting | Primary | Supporting | Supporting |
| Keep tools least-privileged outside the model | Supporting | Primary | Primary | Primary | Supporting | Supporting |
| Scan retrieved chunks from RAG pipelines | Primary | Supporting | Supporting | Supporting | Supporting | Primary |
| Keep audit logs for scans and tool decisions | Supporting | Supporting | Primary | Primary | Supporting | Supporting |

## Residual Risk Statement

Agent Prompt Shield materially reduces exposure to known prompt-injection and tool-hijack patterns, especially at the text-ingestion and tool-execution boundaries. The remaining risk is not incidental; it is inherent to deterministic lexical defenses operating inside broader agent systems.

The highest residual risks are:

- semantic prompt injections that avoid known indicators
- multi-turn attacks where no single chunk is clearly malicious
- RAG authorization failures that occur before text reaches the scanner
- overprivileged tools or permissive allow lists
- host applications that ignore blocked decisions or fail to preserve trust boundaries
- prompt or secret leakage through model behavior rather than direct text requests
- hidden multimodal instructions outside the current text-only scanner

The recommended deployment posture is defense in depth:

- scan all untrusted text
- keep untrusted content visibly labeled as data
- gate every tool call
- require approval for irreversible or public actions
- isolate credentials
- restrict tool permissions
- log scan and tool decisions
- test bypasses continuously
- treat new failures as regression cases

## Research Posture

This project should be described as a research-grade alpha guardrail, not as a production security boundary. Strong claims should be limited to measured behavior under the repository's test and benchmark corpora.

Acceptable claims:

- deterministic, auditable scanner for known prompt-injection patterns
- tool-gating policy layer for agent applications
- benchmarked against synthetic, real-world-inspired, benign, and adversarial/failure-analysis corpora
- useful as one layer in a defense-in-depth agent stack

Claims to avoid:

- solves prompt injection
- prevents all jailbreaks
- makes agents safe
- replaces sandboxing or approvals
- protects all RAG systems
- enterprise-grade AI firewall

Security progress for this project should come from better evaluation, external bypass attempts, clearer failure analysis, and stronger integration case studies rather than inflated marketing language.
