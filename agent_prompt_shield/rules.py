from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .models import Finding


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: int
    message: str
    pattern: re.Pattern[str]

    def find(self, text: str) -> Iterable[Finding]:
        for match in self.pattern.finditer(text):
            evidence = " ".join(match.group(0).split())
            if len(evidence) > 160:
                evidence = evidence[:157] + "..."
            yield Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                message=self.message,
                evidence=evidence,
                start=match.start(),
                end=match.end(),
            )


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        "role_override.ignore_instructions",
        "role_override",
        35,
        "Attempts to override prior instructions.",
        _rx(r"\b(ignore|disregard|forget|bypass|override)\b.{0,80}\b(previous|prior|above|system|developer|original)\b.{0,40}\b(instruction|prompt|message|rule)s?\b"),
    ),
    Rule(
        "role_override.new_role",
        "role_override",
        25,
        "Attempts to assign a new identity or policy.",
        _rx(r"\b(you are now|act as|from now on|new role|developer mode|jailbreak mode)\b"),
    ),
    Rule(
        "role_override.multilingual_ignore_prior",
        "role_override",
        60,
        "Uses non-English instruction-override language.",
        _rx(r"\b(ignora|olvida|omite|descarta|ignorez|oublie|ne\s+tiens\s+pas\s+compte|ignori|dimentica)\b.{0,80}\b(instrucciones|instructions?|indicaciones|system|sistema|developer|desarrollador|precedentes?|anteriores?|previous|prior)\b"),
    ),
    Rule(
        "role_override.roleplay_bypass",
        "role_override",
        60,
        "Uses roleplay or translation framing to bypass instructions.",
        _rx(r"\b(translate|traduce|roleplay|pretend|simula|actua\s+como)\b.{0,100}\b(ignore|bypass|override|jailbreak|developer mode|do not translate|instead)\b.{0,80}\b(instruction|prompt|policy|rule|safety|system|developer)s?\b"),
    ),
    Rule(
        "secret_exfiltration.direct",
        "secret_exfiltration",
        60,
        "Requests secrets, credentials, or hidden prompts.",
        _rx(r"\b(reveal|print|dump|show|send|exfiltrate|leak)\b.{0,80}\b(api[_ -]?key|token|password|secret|credential|private key|system prompt|hidden prompt|developer message)s?\b"),
    ),
    Rule(
        "secret_exfiltration.system_prompt_extraction",
        "secret_exfiltration",
        60,
        "Requests disclosure of hidden system or developer instructions.",
        _rx(r"\b(reveal|print|dump|show|extract|quote|copy|repeat)\b.{0,80}\b(system|developer|hidden|initial|original)\b.{0,40}\b(prompt|message|instruction|policy|rule)s?\b"),
    ),
    Rule(
        "secret_exfiltration.destination",
        "secret_exfiltration",
        40,
        "Tries to send sensitive data to an external destination.",
        _rx(r"\b(send|post|upload|email|dm|message|fetch|curl)\b.{0,100}\b(http[s]?://|@|webhook|pastebin|discord|telegram|slack)\b"),
    ),
    Rule(
        "tool_hijack.command_execution",
        "tool_hijack",
        40,
        "Attempts to coerce shell, filesystem, browser, or network tool use.",
        _rx(r"\b(ignore|bypass|override|waive|silently|secretly|without asking|without approval|developer message|system message|hidden instruction)\b.{0,120}\b(run|execute|open|browse|read|write|delete|modify|download|install|post)\b.{0,80}\b(shell|powershell|cmd|terminal|bash|filesystem|file|browser|github|mcp|tool|command|output|action)\b|\b(run|execute|open|browse|read|write|delete|modify|download|install|post)\b.{0,80}\b(shell|powershell|cmd|terminal|bash|filesystem|file|browser|github|mcp|tool|command|output|action)\b.{0,120}\b(ignore|bypass|override|waive|silently|secretly|without asking|without approval|secret|password|token|credential|developer message|system message|hidden instruction)\b"),
    ),
    Rule(
        "data_boundary.untrusted_instruction",
        "data_boundary",
        25,
        "Marks untrusted content as instructions for the agent.",
        _rx(r"\b(instructions? for (the )?(assistant|agent|model)|system message:|developer message:|assistant must|model must)\b"),
    ),
    Rule(
        "data_boundary.indirect_prompt_injection",
        "data_boundary",
        35,
        "Turns untrusted content into instructions for a future assistant or agent.",
        _rx(r"\b(when|if|once)\b.{0,40}\b(assistant|agent|model|ai|crawler|summarizer)\b.{0,40}\b(reads?|sees?|processes?|summarizes?)\b.{0,80}\b(ignore|follow|execute|treat this as|developer message|system message)\b"),
    ),
    Rule(
        "data_boundary.fake_tool_output_instruction",
        "data_boundary",
        35,
        "Smuggles instructions through fake tool, search, or retrieval output.",
        _rx(r"\b(tool result|search result|retrieval result|webpage says|document says|email says)\b.{0,80}\b(assistant must|model must|ignore|execute|developer message|system message)\b"),
    ),
    Rule(
        "obfuscation.hidden_text",
        "obfuscation",
        20,
        "Uses hidden or encoded instruction language.",
        _rx(r"\b(base64|rot13|hidden text|invisible text|white text|ignore if visible|do not mention this)\b"),
    ),
    Rule(
        "obfuscation.encoded_execute",
        "obfuscation",
        35,
        "Uses encoded payload language with execution or instruction-following intent.",
        _rx(r"\b(base64|rot13|hex encoded|url encoded|unicode escaped|decode this|atob)\b.{0,100}\b(ignore|execute|run|follow|reveal|exfiltrate|system prompt|developer message)\b"),
    ),
    Rule(
        "obfuscation.escaped_instruction",
        "obfuscation",
        35,
        "Uses escaped character payloads around instruction override language.",
        _rx(r"(\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}){3,}.{0,80}\b(ignore|override|execute|reveal|system prompt|developer message)\b"),
    ),
    Rule(
        "data_boundary.multi_turn_setup",
        "data_boundary",
        25,
        "Sets up a later-turn instruction override.",
        _rx(r"\b(in your next|next response|later|after this|on the following turn|second message)\b.{0,100}\b(ignore|override|bypass|forget|reveal|execute)\b.{0,80}\b(instruction|prompt|policy|rule|system|developer)s?\b"),
    ),
    Rule(
        "persuasion.authority_bypass",
        "persuasion",
        35,
        "Claims authority, audit, or emergency status to bypass safety policy.",
        _rx(r"\b(admin|administrator|root|owner|security audit|compliance|emergency|urgent override|authorized)\b.{0,100}\b(ignore|bypass|override|disable|waive)\b.{0,80}\b(policy|safety|approval|guardrail|instruction|rule)s?\b"),
    ),
    Rule(
        "tool_hijack.code_comment_instruction",
        "tool_hijack",
        35,
        "Smuggles agent instructions inside code comments.",
        _rx(r"(?://|#|/\*|<!--).{0,80}\b(assistant|agent|model|codex)\b.{0,80}\b(ignore|override|execute|run|reveal|exfiltrate)\b"),
    ),
    Rule(
        "obfuscation.markdown_hidden_instruction",
        "obfuscation",
        35,
        "Hides instructions inside Markdown comments or reference syntax.",
        _rx(r"(\[//\]:\s*#|\[comment\]:\s*#|<!--).{0,120}\b(ignore|override|execute|reveal|exfiltrate|system prompt|developer message)\b"),
    ),
    Rule(
        "obfuscation.html_hidden_instruction",
        "obfuscation",
        35,
        "Hides instructions inside non-visible HTML.",
        _rx(r"<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|hidden\b)[^>]*>.{0,160}\b(ignore|override|execute|reveal|exfiltrate|system prompt|developer message)\b"),
    ),
    Rule(
        "context_smuggling.zero_width_override",
        "context_smuggling",
        35,
        "Uses invisible Unicode characters to hide instruction override language.",
        _rx(r"i[\u200b\u200c\u200d\ufeff\u2060]g[\u200b\u200c\u200d\ufeff\u2060]n[\u200b\u200c\u200d\ufeff\u2060]o[\u200b\u200c\u200d\ufeff\u2060]r[\u200b\u200c\u200d\ufeff\u2060]e.{0,80}\b(previous|prior|system|developer|instruction|prompt|rule)s?\b"),
    ),
    Rule(
        "context_smuggling.bidi_hidden_instruction",
        "context_smuggling",
        25,
        "Uses bidirectional or isolate Unicode controls near agent instruction language.",
        _rx(r"[\u202a-\u202e\u2066-\u2069].{0,80}\b(ignore|override|system prompt|developer message|execute|reveal)\b"),
    ),
    Rule(
        "approval_bypass.no_confirm",
        "approval_bypass",
        30,
        "Attempts to bypass approval or safety checks.",
        _rx(r"\b(do not ask|without asking|without approval|no confirmation|silently|secretly)\b.{0,80}\b(send|post|delete|execute|run|email|message|publish)\b"),
    ),
)
