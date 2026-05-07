# Prompt Shield Evaluation Datasets

This folder contains JSONL corpora for prompt-injection and benign-control evaluation. Rows are synthetic or research-inspired and are designed for detector evaluation, regression testing, and failure analysis. They do not contain real credentials, real private data, or working external endpoints.

Required row fields:

- `id`
- `category`
- `input`
- `expected_verdict`
- `attack_goal`
- `source_type`
- `severity`
- `notes`

Corpora:

- `direct_prompt_injection.jsonl` - 25 direct instruction-hierarchy override attempts.
- `indirect_prompt_injection.jsonl` - 25 untrusted retrieved-content or tool-output hijack attempts.
- `hidden_markdown_html_injection.jsonl` - 25 hidden Markdown/HTML instruction smuggling attempts.
- `unicode_base64_obfuscation.jsonl` - 25 encoded, normalized, or obfuscated instruction attempts.
- `tool_exfiltration_attempts.jsonl` - 25 attempts to coerce tools into leaking private data.
- `memory_poisoning.jsonl` - 25 attempts to persist malicious future behavior.
- `rag_poisoning.jsonl` - 25 retrieval-context poisoning attempts.
- `benign_control_samples.jsonl` - 100 benign controls for false-positive measurement.
