from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent_prompt_shield import PromptShield, Verdict
from agent_prompt_shield.rules import DEFAULT_RULES

ATTACKS_PATH = ROOT / "attacks.json"
REAL_WORLD_ATTACKS_PATH = ROOT / "real_world_attacks.json"
ADVERSARIAL_BYPASS_PATH = ROOT / "adversarial_bypass.json"
BENIGN_PATH = ROOT / "benign.json"
RESULTS_PATH = ROOT / "results.json"

NAIVE_BASELINE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("ignore_previous", r"\bignore (all )?(previous|prior|earlier|system|developer) (instructions|rules|constraints|message|policy)\b"),
    ("system_prompt", r"\b(system prompt|developer message|developer prompt|hidden prompt|hidden instructions|initial instructions)\b"),
    ("bypass_policy", r"\b(bypass|override|disable|waive|forget|discard).{0,50}\b(policy|rules|safety|guardrail|approval|instructions)\b"),
    ("secret_exfiltration", r"\b(api key|token|password|private key|credentials|secrets?)\b"),
    ("external_destination", r"\b(webhook|slack|attacker@example\.com|collector\.example|post it|send .* to)\b"),
    ("encoded_payload", r"\b(base64|rot13|url encoded|unicode escaped|decode this)\b"),
    ("hidden_markup", r"(<!--|display\s*:\s*none|<div hidden|<span[^>]+hidden|\[//\]:)"),
    ("tool_coercion", r"\b(execute|run|open).{0,50}\b(tool|command|powershell|filesystem|browser)\b"),
    ("approval_bypass", r"\b(without asking|do not ask for confirmation|silently|approval rules?)\b"),
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def finding_summary(result: Any) -> list[dict[str, Any]]:
    return [
        {
            "rule_id": finding.rule_id,
            "category": finding.category,
            "severity": finding.severity,
            "evidence": finding.evidence,
        }
        for finding in result.findings
    ]


def pct(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)


def naive_baseline_hits(text: str) -> list[str]:
    return [
        rule_id
        for rule_id, pattern in NAIVE_BASELINE_PATTERNS
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    ]


def summarize_naive_baseline(
    attacks: list[dict[str, Any]], benign: list[dict[str, Any]]
) -> dict[str, Any]:
    attack_detections = []
    benign_false_positives = []
    corpus_totals: dict[str, int] = defaultdict(int)
    corpus_detected: dict[str, int] = defaultdict(int)

    for item in attacks:
        corpus = item["corpus"]
        hits = naive_baseline_hits(item["text"])
        detected = bool(hits)
        corpus_totals[corpus] += 1
        if detected:
            corpus_detected[corpus] += 1
        attack_detections.append(
            {
                "id": item["id"],
                "corpus": corpus,
                "category": item["category"],
                "detected": detected,
                "matched_patterns": hits,
            }
        )

    for item in benign:
        hits = naive_baseline_hits(item["text"])
        if hits:
            benign_false_positives.append(
                {
                    "id": item["id"],
                    "category": item["category"],
                    "text": item["text"],
                    "matched_patterns": hits,
                }
            )

    per_corpus = {}
    for corpus in sorted(corpus_totals):
        total = corpus_totals[corpus]
        detected = corpus_detected[corpus]
        per_corpus[corpus] = {
            "total": total,
            "detected": detected,
            "detection_rate": pct(detected, total),
        }

    detected_total = sum(1 for item in attack_detections if item["detected"])
    return {
        "description": "Simple keyword/regex baseline for calibration only; it has no scoring, severities, categories, Unicode normalization, or tool-risk policy.",
        "pattern_count": len(NAIVE_BASELINE_PATTERNS),
        "attacks_detected": detected_total,
        "attacks_total": len(attacks),
        "attack_detection_rate": pct(detected_total, len(attacks)),
        "benign_false_positives": len(benign_false_positives),
        "benign_total": len(benign),
        "false_positive_rate": pct(len(benign_false_positives), len(benign)),
        "per_corpus_detection": per_corpus,
        "missed_attack_ids": [
            item["id"] for item in attack_detections if not item["detected"]
        ],
        "false_positives": benign_false_positives,
        "patterns": [
            {"id": rule_id, "pattern": pattern}
            for rule_id, pattern in NAIVE_BASELINE_PATTERNS
        ],
    }


def summarize_adversarial_bypass(
    shield: PromptShield,
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    results = []
    caught_count = 0
    blocked_count = 0
    expected_alignment_count = 0
    limitation_count = 0

    for item in cases:
        result = shield.scan(item["text"])
        caught = result.verdict in {Verdict.SUSPICIOUS, Verdict.BLOCKED}
        blocked = result.verdict == Verdict.BLOCKED
        expected = item["expected_verdict"]
        aligns = result.verdict.value == expected
        if caught:
            caught_count += 1
        if blocked:
            blocked_count += 1
        if aligns:
            expected_alignment_count += 1
        if item.get("intended_use") == "known_limitation":
            limitation_count += 1
        results.append(
            {
                "id": item["id"],
                "category": item["category"],
                "intended_use": item.get("intended_use"),
                "expected_verdict": expected,
                "actual_verdict": result.verdict.value,
                "score": result.score,
                "caught": caught,
                "blocked": blocked,
                "expected_alignment": aligns,
                "attack_goal": item.get("attack_goal"),
                "notes": item.get("notes"),
                "findings": finding_summary(result),
            }
        )

    return {
        "description": "Adversarial bypass and failure-analysis corpus. This suite is reported separately from headline benchmark numbers so known limitations are visible instead of hidden.",
        "total": len(cases),
        "known_limitations": limitation_count,
        "caught": caught_count,
        "caught_rate": pct(caught_count, len(cases)),
        "blocked": blocked_count,
        "blocked_rate": pct(blocked_count, len(cases)),
        "expected_alignment": expected_alignment_count,
        "expected_alignment_rate": pct(expected_alignment_count, len(cases)),
        "cases": results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Agent Prompt Shield benchmarks.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if calibrated headline benchmark thresholds regress.",
    )
    parser.add_argument(
        "--min-attack-caught-rate",
        type=float,
        default=100.0,
        help="Minimum suspicious-or-blocked attack catch rate for --check.",
    )
    parser.add_argument(
        "--min-attack-blocked-rate",
        type=float,
        default=95.0,
        help="Minimum blocked-only attack rate for --check.",
    )
    parser.add_argument(
        "--max-benign-false-positive-rate",
        type=float,
        default=1.0,
        help="Maximum benign false-positive rate for --check.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    synthetic_attacks = load_json(ATTACKS_PATH)["attacks"]
    real_world_attacks = load_json(REAL_WORLD_ATTACKS_PATH)["attacks"]
    adversarial_bypass = load_json(ADVERSARIAL_BYPASS_PATH)["cases"]
    attack_sets = (
        ("synthetic", synthetic_attacks),
        ("real_world_inspired", real_world_attacks),
    )
    attacks = [
        {**item, "corpus": corpus}
        for corpus, items in attack_sets
        for item in items
    ]
    benign = load_json(BENIGN_PATH)["queries"]
    shield = PromptShield()

    attack_results = []
    benign_results = []
    category_totals: dict[str, int] = defaultdict(int)
    category_suspicious_or_blocked: dict[str, int] = defaultdict(int)
    category_blocked: dict[str, int] = defaultdict(int)
    corpus_totals: dict[str, int] = defaultdict(int)
    corpus_suspicious_or_blocked: dict[str, int] = defaultdict(int)
    corpus_blocked: dict[str, int] = defaultdict(int)
    source_totals: dict[str, int] = defaultdict(int)
    source_suspicious_or_blocked: dict[str, int] = defaultdict(int)
    source_blocked: dict[str, int] = defaultdict(int)

    blocked_attacks = 0
    suspicious_or_blocked_attacks = 0
    missed_attacks = []

    for item in attacks:
        result = shield.scan(item["text"])
        is_blocked = result.verdict == Verdict.BLOCKED
        is_caught = result.verdict in {Verdict.SUSPICIOUS, Verdict.BLOCKED}
        category = item["category"]
        corpus = item["corpus"]
        source = item.get("source") or item.get("inspired_by") or "unlabeled"

        category_totals[category] += 1
        corpus_totals[corpus] += 1
        source_totals[source] += 1
        if is_blocked:
            blocked_attacks += 1
            category_blocked[category] += 1
            corpus_blocked[corpus] += 1
            source_blocked[source] += 1
        if is_caught:
            suspicious_or_blocked_attacks += 1
            category_suspicious_or_blocked[category] += 1
            corpus_suspicious_or_blocked[corpus] += 1
            source_suspicious_or_blocked[source] += 1
        else:
            missed_attacks.append(
                {
                    "id": item["id"],
                    "corpus": corpus,
                    "source": source,
                    "source_url": item.get("source_url"),
                    "scenario": item.get("scenario"),
                    "category": category,
                    "text": item["text"],
                    "verdict": result.verdict.value,
                    "score": result.score,
                    "findings": finding_summary(result),
                }
            )

        attack_results.append(
            {
                "id": item["id"],
                "corpus": corpus,
                "source": source,
                "source_url": item.get("source_url"),
                "scenario": item.get("scenario"),
                "category": category,
                "expected_verdict": item["expected_verdict"],
                "actual_verdict": result.verdict.value,
                "score": result.score,
                "caught": is_caught,
                "blocked": is_blocked,
                "findings": finding_summary(result),
            }
        )

    false_positives = []
    for item in benign:
        result = shield.scan(item["text"])
        is_false_positive = result.verdict in {Verdict.SUSPICIOUS, Verdict.BLOCKED}
        if is_false_positive:
            false_positives.append(
                {
                    "id": item["id"],
                    "category": item["category"],
                    "text": item["text"],
                    "verdict": result.verdict.value,
                    "score": result.score,
                    "findings": finding_summary(result),
                }
            )

        benign_results.append(
            {
                "id": item["id"],
                "category": item["category"],
                "actual_verdict": result.verdict.value,
                "score": result.score,
                "false_positive": is_false_positive,
                "findings": finding_summary(result),
            }
        )

    per_category = {}
    for category in sorted(category_totals):
        total = category_totals[category]
        caught = category_suspicious_or_blocked[category]
        blocked = category_blocked[category]
        per_category[category] = {
            "total": total,
            "suspicious_or_blocked": caught,
            "suspicious_or_blocked_rate": pct(caught, total),
            "blocked": blocked,
            "blocked_rate": pct(blocked, total),
        }

    per_corpus = {}
    for corpus in sorted(corpus_totals):
        total = corpus_totals[corpus]
        caught = corpus_suspicious_or_blocked[corpus]
        blocked = corpus_blocked[corpus]
        per_corpus[corpus] = {
            "total": total,
            "suspicious_or_blocked": caught,
            "suspicious_or_blocked_rate": pct(caught, total),
            "blocked": blocked,
            "blocked_rate": pct(blocked, total),
        }

    per_source = {}
    for source in sorted(source_totals):
        total = source_totals[source]
        caught = source_suspicious_or_blocked[source]
        blocked = source_blocked[source]
        per_source[source] = {
            "total": total,
            "suspicious_or_blocked": caught,
            "suspicious_or_blocked_rate": pct(caught, total),
            "blocked": blocked,
            "blocked_rate": pct(blocked, total),
        }

    summary = {
        "current_rule_count": len(DEFAULT_RULES),
        "attacks_total": len(attacks),
        "attacks_blocked": blocked_attacks,
        "attacks_suspicious_or_blocked": suspicious_or_blocked_attacks,
        "true_positive_rate": pct(suspicious_or_blocked_attacks, len(attacks)),
        "blocked_only_rate": pct(blocked_attacks, len(attacks)),
        "suspicious_or_blocked_rate": pct(suspicious_or_blocked_attacks, len(attacks)),
        "benign_total": len(benign),
        "benign_false_positives": len(false_positives),
        "false_positive_rate": pct(len(false_positives), len(benign)),
        "per_corpus_detection": per_corpus,
        "per_category_detection": per_category,
        "per_source_detection": per_source,
        "missed_attacks": missed_attacks,
        "false_positives": false_positives,
        "naive_baseline": summarize_naive_baseline(attacks, benign),
        "adversarial_bypass": summarize_adversarial_bypass(shield, adversarial_bypass),
    }

    output = {
        "summary": summary,
        "attack_results": attack_results,
        "benign_results": benign_results,
    }
    RESULTS_PATH.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Current rule count: {summary['current_rule_count']}")
    print(
        "Attacks: "
        f"{summary['attacks_suspicious_or_blocked']}/{summary['attacks_total']} caught "
        f"({summary['true_positive_rate']}% suspicious-or-blocked), "
        f"{summary['attacks_blocked']}/{summary['attacks_total']} blocked "
        f"({summary['blocked_only_rate']}%)"
    )
    print(
        "Benign: "
        f"{summary['benign_false_positives']}/{summary['benign_total']} false positives "
        f"({summary['false_positive_rate']}%)"
    )
    baseline = summary["naive_baseline"]
    adversarial = summary["adversarial_bypass"]
    print(
        "Naive baseline: "
        f"{baseline['attacks_detected']}/{baseline['attacks_total']} attacks detected "
        f"({baseline['attack_detection_rate']}%), "
        f"{baseline['benign_false_positives']}/{baseline['benign_total']} benign false positives "
        f"({baseline['false_positive_rate']}%)"
    )
    print("Per-category detection:")
    for category, stats in per_category.items():
        print(
            f"  {category}: "
            f"{stats['suspicious_or_blocked']}/{stats['total']} caught "
            f"({stats['suspicious_or_blocked_rate']}%), "
            f"{stats['blocked']}/{stats['total']} blocked "
            f"({stats['blocked_rate']}%)"
        )
    print("Per-corpus detection:")
    for corpus, stats in per_corpus.items():
        print(
            f"  {corpus}: "
            f"{stats['suspicious_or_blocked']}/{stats['total']} caught "
            f"({stats['suspicious_or_blocked_rate']}%), "
            f"{stats['blocked']}/{stats['total']} blocked "
            f"({stats['blocked_rate']}%)"
        )
    print("Per-source detection:")
    for source, stats in per_source.items():
        print(
            f"  {source}: "
            f"{stats['suspicious_or_blocked']}/{stats['total']} caught "
            f"({stats['suspicious_or_blocked_rate']}%), "
            f"{stats['blocked']}/{stats['total']} blocked "
            f"({stats['blocked_rate']}%)"
        )
    print(
        "Adversarial bypass suite: "
        f"{adversarial['caught']}/{adversarial['total']} caught "
        f"({adversarial['caught_rate']}%), "
        f"{adversarial['blocked']}/{adversarial['total']} blocked "
        f"({adversarial['blocked_rate']}%), "
        f"{adversarial['expected_alignment']}/{adversarial['total']} expected outcomes "
        f"({adversarial['expected_alignment_rate']}%)"
    )
    print(f"Results saved to: {RESULTS_PATH}")

    if args.check:
        failures = []
        if summary["true_positive_rate"] < args.min_attack_caught_rate:
            failures.append(
                "attack catch rate "
                f"{summary['true_positive_rate']}% < {args.min_attack_caught_rate}%"
            )
        if summary["blocked_only_rate"] < args.min_attack_blocked_rate:
            failures.append(
                "attack blocked rate "
                f"{summary['blocked_only_rate']}% < {args.min_attack_blocked_rate}%"
            )
        if summary["false_positive_rate"] > args.max_benign_false_positive_rate:
            failures.append(
                "benign false-positive rate "
                f"{summary['false_positive_rate']}% > {args.max_benign_false_positive_rate}%"
            )
        if failures:
            print("Benchmark check failed:")
            for failure in failures:
                print(f"  - {failure}")
            raise SystemExit(1)
        print("Benchmark check passed.")


if __name__ == "__main__":
    main()
