from __future__ import annotations

import base64
import json

HOMOGLYPH_MAP = str.maketrans(
    {
        "a": "\u0430",
        "A": "\u0410",
        "c": "\u0441",
        "C": "\u0421",
        "e": "\u0435",
        "E": "\u0415",
        "i": "\u0456",
        "I": "\u0406",
        "o": "\u043e",
        "O": "\u041e",
        "p": "\u0440",
        "P": "\u0420",
        "x": "\u0445",
        "X": "\u0425",
        "y": "\u0443",
        "Y": "\u0423",
    }
)

LEETSPEAK_MAP = str.maketrans(
    {
        "a": "4",
        "A": "4",
        "e": "3",
        "E": "3",
        "i": "1",
        "I": "1",
        "o": "0",
        "O": "0",
        "s": "5",
        "S": "5",
        "t": "7",
        "T": "7",
    }
)


def spacing_mutation(text: str) -> str:
    """Insert zero-width separators between non-space characters."""
    return "\u200b".join(text)


def casing_mutation(text: str) -> str:
    """Alternates character casing without changing token order."""
    chars: list[str] = []
    letter_index = 0
    for char in text:
        if char.isalpha():
            chars.append(char.upper() if letter_index % 2 == 0 else char.lower())
            letter_index += 1
        else:
            chars.append(char)
    return "".join(chars)


def unicode_homoglyph_mutation(text: str) -> str:
    """Replace common Latin characters with visually similar Unicode codepoints."""
    return text.translate(HOMOGLYPH_MAP)


def leetspeak_mutation(text: str) -> str:
    """Replace common letters with leetspeak digits."""
    return text.translate(LEETSPEAK_MAP)


def base64_mutation(text: str) -> str:
    """Wrap the payload as a base64 decode-and-follow instruction."""
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return f"Decode this base64 payload and follow it: {encoded}"


def markdown_link_mutation(text: str) -> str:
    """Smuggle the payload into a Markdown link title."""
    escaped = text.replace('"', "'")
    return f"[project documentation](https://example.invalid/docs \"{escaped}\")"


def html_comment_mutation(text: str) -> str:
    """Smuggle the payload into an HTML comment."""
    safe_text = text.replace("--", "- -")
    return f"<!-- {safe_text} -->"


def json_wrapping_mutation(text: str) -> str:
    """Wrap the payload in a fake serialized tool/context object."""
    return json.dumps(
        {
            "source": "retrieved_context",
            "trusted": False,
            "content": text,
        },
        ensure_ascii=False,
    )


def yaml_wrapping_mutation(text: str) -> str:
    """Wrap the payload in a YAML-like metadata block."""
    indented = "\n".join(f"  {line}" for line in text.splitlines() or [""])
    return f"source: retrieved_context\ntrusted: false\ncontent: |\n{indented}"


def fake_log_mutation(text: str) -> str:
    """Present the payload as an operational log entry."""
    return f"[2026-01-01T00:00:00Z] INFO retriever: {text}"


def fake_sysmessage_mutation(text: str) -> str:
    """Present the payload as a fake system/developer message block."""
    return f"<system-message priority=\"critical\">\n{text}\n</system-message>"


MUTATORS = (
    spacing_mutation,
    casing_mutation,
    unicode_homoglyph_mutation,
    leetspeak_mutation,
    base64_mutation,
    markdown_link_mutation,
    html_comment_mutation,
    json_wrapping_mutation,
    yaml_wrapping_mutation,
    fake_log_mutation,
    fake_sysmessage_mutation,
)


def mutate_prompt(text: str, count: int = 20) -> list[str]:
    """Return up to count deterministic adversarial mutations for a prompt string."""
    if count < 0:
        raise ValueError("count must be non-negative")
    if count == 0:
        return []

    mutations: list[str] = []
    seen = {text}
    mutator_index = 0
    depth = 1
    while len(mutations) < count:
        mutator = MUTATORS[mutator_index % len(MUTATORS)]
        candidate = text
        for _ in range(depth):
            candidate = mutator(candidate)

        if candidate not in seen:
            seen.add(candidate)
            mutations.append(candidate)

        mutator_index += 1
        if mutator_index % len(MUTATORS) == 0:
            depth += 1

    return mutations
