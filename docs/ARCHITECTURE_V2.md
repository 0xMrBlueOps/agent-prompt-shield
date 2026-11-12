# Agent Prompt Shield v2 — Architecture Specification

**Maintainer:** `0xMrBlueOps` (`@Mr.Redman28x`)  
**Design Goal:** Evolve `agent-prompt-shield` from a single-turn regex scanner into a zero-external-dependency (Python stdlib-only), deterministic runtime security harness and adversarial evaluation engine aligned with open-source frontier red-teaming tooling ([T3MP3ST](https://github.com/elder-plinius/T3MP3ST), [OBLITERATUS](https://github.com/elder-plinius/OBLITERATUS), and [P4RS3LT0NGV3](https://github.com/elder-plinius/P4RS3LT0NGV3)).

---

## 1. Target Models & Agent Runtimes

- **Agent Runtimes:**
  - [T3MP3ST](https://github.com/elder-plinius/T3MP3ST) MCP server (`security_recon`) and autonomous kill-chain operators
  - [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent/issues/15876) (`computer_use_tool.py` / containerized noVNC desktop execution)
  - Local coding-agent harnesses (Claude Code, Codex, OpenCode)
- **Target Model Tiers:**
  - Frontier API models (Claude Fable 5.2 / Opus 5.5, GPT-5.5 / GPT-6, DeepSeek V4, Grok 4.7)
  - Local Ollama/vLLM checkpoints, including abliterated open-weight baselines generated via [OBLITERATUS](https://github.com/elder-plinius/OBLITERATUS) (Llama-3.1-8B, Qwen2.5-7B, DeepSeek-R1 distills)

---

## 2. Attack Vectors & Defense Modules

### 2.1 Counter-Obfuscation Normalization (`normalizer.py` + `scanner.py`)
Pre-scan deterministic decoding pipeline targeting [P4RS3LT0NGV3](https://github.com/elder-plinius/P4RS3LT0NGV3) transforms:
- **Steganography & Invisible Payloads:** Unicode Tags (`U+E0000`–`U+E007F`), emoji variation-selector bitstreams (`VS15`/`VS16`), zero-width joiners/spaces, and whitespace steganography.
- **Visual & Tokenization Evasion:** Cyrillic/mathematical homoglyph folding, Zalgo combining-mark stripping, and `Tokenade`-style token-bomb density/ratio caps.
- **Encoding & Delimiter Smuggling:** Recursive decoding for Base32/58/64/85/91, ROT13/47, and special token/delimiter injection (`<|im_end|>`, `<|endoftext|>`, `<<SYS>>`).

### 2.2 Kinetic & Multi-Turn Tool Gating (`gate.py` + `ledger.py`)
Stateful pre- and post-execution hooks for MCP and desktop tool loops:
- **Indirect Prompt Injection:** Sanitizes and flags untrusted tool outputs (web scrapes, API responses, logs) before re-injection into the model context.
- **Cross-Turn Fragmentation ("Pack Hunt" Defense):** Tracks rolling session risk scores across turns in `ledger.py` to catch split payloads assembled over multiple messages.
- **Egress & Execution Containment:** Enforces declarative allowlists, path-traversal checks, and `T3MP3ST`-style `SCOPE DENIED` host/SSRF egress boundaries on tool arguments.

---

## 3. Telemetry & Reproducible Verification (`audit.py` + `verify_claims`)

- **JSONL Schema (`shield_telemetry_v2.jsonl`):** Records `run_id`, `session_id`, `turn_index`, `model_id`, `abliteration_state`, `attack_category`, `transform_chain`, `hook_stage` (`pre_prompt` | `pre_tool` | `post_tool`), `decision` (`ALLOW` | `SANITIZE` | `BLOCK`), `latency_us`, and `sha256_evidence_receipt` (no raw PII or plaintext prompts stored).
- **Re-derivable Benchmarks (`python -m agent_prompt_shield.verify_claims`):** Recomputes detection rates, false-positive rates, and p95 latency from committed benchmark JSON artifacts.
