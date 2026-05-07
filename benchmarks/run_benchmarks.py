from __future__ import annotations

import json
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
BENIGN_PATH = ROOT / "benign.json"
RESULTS_PATH = ROOT / "results.json"


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


def main() -> None:
    attacks = load_json(ATTACKS_PATH)["attacks"]
    benign = load_json(BENIGN_PATH)["queries"]
    shield = PromptShield()

    attack_results = []
    benign_results = []
    category_totals: dict[str, int] = defaultdict(int)
    category_suspicious_or_blocked: dict[str, int] = defaultdict(int)
    category_blocked: dict[str, int] = defaultdict(int)

    blocked_attacks = 0
    suspicious_or_blocked_attacks = 0
    missed_attacks = []

    for item in attacks:
        result = shield.scan(item["text"])
        is_blocked = result.verdict == Verdict.BLOCKED
        is_caught = result.verdict in {Verdict.SUSPICIOUS, Verdict.BLOCKED}
        category = item["category"]

        category_totals[category] += 1
        if is_blocked:
            blocked_attacks += 1
            category_blocked[category] += 1
        if is_caught:
            suspicious_or_blocked_attacks += 1
            category_suspicious_or_blocked[category] += 1
        else:
            missed_attacks.append(
                {
                    "id": item["id"],
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
        "per_category_detection": per_category,
        "missed_attacks": missed_attacks,
        "false_positives": false_positives,
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
    print("Per-category detection:")
    for category, stats in per_category.items():
        print(
            f"  {category}: "
            f"{stats['suspicious_or_blocked']}/{stats['total']} caught "
            f"({stats['suspicious_or_blocked_rate']}%), "
            f"{stats['blocked']}/{stats['total']} blocked "
            f"({stats['blocked_rate']}%)"
        )
    print(f"Results saved to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
