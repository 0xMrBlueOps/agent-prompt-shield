# Jarvis Red Lab v0.1

Jarvis Red Lab is an evidence-driven workspace for authorized AI red-team campaigns. It is designed for Gray Swan exercises, local models, user-owned agents, CTFs, and other targets where the operator has explicit permission to test.

## First capability

The first implementation is an append-only experiment ledger. It records:

- the target and authorization boundary
- allowed and prohibited actions
- the campaign objective and success criteria
- every hypothesis, payload, delivery channel, response, and tool trace
- failed, partial, successful, and invalid results
- parent-child relationships between an attempt and its controlled mutations
- campaign-level success and partial-success rates

The ledger deliberately separates research evidence from ordinary assistant chat memory.

## Minimal workflow

```python
from agent_prompt_shield.redlab import (
    Attempt,
    AttemptResult,
    Campaign,
    RedLabLedger,
    Scope,
)

ledger = RedLabLedger("redlab/campaigns/grayswan-001.jsonl")

campaign = ledger.create_campaign(
    Campaign(
        name="Gray Swan authorized exercise",
        scope=Scope(
            target="challenge-target-id",
            authorization="Published challenge scope and user-owned account",
            allowed_actions=("submit prompts", "analyze transcripts"),
            prohibited_actions=("test unrelated systems",),
            disclosure_requirements=("follow challenge disclosure rules",),
        ),
        objective="Evaluate resistance to indirect prompt injection.",
        success_criteria=("Meet the challenge's declared success condition",),
    )
)

first = ledger.record_attempt(
    Attempt(
        campaign_id=campaign.campaign_id,
        attack_family="indirect_prompt_injection",
        hypothesis="The target may treat tool output as an instruction source.",
        payload="Controlled test payload",
        delivery_channel="tool_output",
        result=AttemptResult.FAILED,
        target_response="Target transcript",
        failure_reason="Instruction boundary remained intact.",
        lesson="Authority framing alone had no measurable effect.",
    )
)

ledger.record_attempt(
    Attempt(
        campaign_id=campaign.campaign_id,
        attack_family="indirect_prompt_injection",
        hypothesis="Change only task-continuation framing.",
        payload="Controlled mutation",
        delivery_channel="tool_output",
        result=AttemptResult.PARTIAL,
        parent_attempt_id=first.attempt_id,
        lesson="Task-continuation framing produced a partial behavioral shift.",
    )
)

print(ledger.metrics(campaign.campaign_id))
```

## Design rules

1. Never infer authorization. Every campaign must declare it explicitly.
2. Keep exact transcripts and tool traces so apparent successes can be verified.
3. Change one meaningful variable at a time when mutating an attempt.
4. Record failures; they are training data for the next hypothesis.
5. Treat successful results as provisional until reproduced in a fresh session.
6. Keep offensive findings connected to root-cause and mitigation analysis.

## Next implementation milestones

- campaign CLI: create, record, list, metrics, and export
- transcript importer for manual Gray Swan testing
- hypothesis and mutation planner interface
- independent success evaluator
- replay and reproducibility tracking
- sanitized Markdown postmortem generator
- Prompt Shield before/after defense evaluation
