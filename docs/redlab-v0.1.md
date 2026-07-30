# Jarvis Red Lab v0.1

Jarvis Red Lab is an evidence-driven workflow for AI-security testing on systems the operator owns or is explicitly authorized to assess.

## Completed v0.1 loop

```text
campaign scope
→ record baseline attempt
→ complete attempt with transcript and trace
→ request controlled strategy proposals
→ review pending drafts
→ accept one proposal as a child attempt
→ execute it manually or through an authorized runner
→ complete the child attempt
→ independently evaluate the evidence
→ replay the apparent success
→ confirm or reject the finding
→ export a reproducible campaign report
```

## Core commands

```bash
agent-redlab init ...
agent-redlab record ...
agent-redlab complete-attempt --attempt <ID> --result failed --response-file transcript.txt
agent-redlab strategy --attempt <ID> --dry-run
agent-redlab strategy --attempt <ID>
agent-redlab drafts --status pending
agent-redlab accept-draft --draft <ID> --channel manual_challenge
agent-redlab reject-draft --draft <ID> --reason "..."
agent-redlab evaluate-model --attempt <ID> --dry-run
agent-redlab evaluate-model --attempt <ID>
agent-redlab verify-replay ...
agent-redlab status --attempt <ID>
agent-redlab metrics --campaign <ID>
agent-redlab report --campaign <ID> --output report.md
```

## Evidence rules

- The JSONL ledger is append-only.
- Accepted strategy drafts create `invalid` attempts until real evidence is recorded.
- `complete-attempt` materializes the final result without creating a duplicate experiment.
- A completed attempt cannot be overwritten.
- A claimed success is not confirmed by the attacker or strategist.
- Confirmation requires both an independent criterion-level evaluation and passing replay verification.
- Reports distinguish raw successes from confirmed reproducible successes.

## Model roles

The strategist and evaluator are separate roles.

The strategist may propose controlled next experiments based on failed or partial evidence. It must preserve campaign scope, parent lineage, expected signals, and stop conditions.

The evaluator receives the exact campaign criteria, payload, transcript, and tool trace. It treats the claimed result as untrusted and returns strict structured findings. It does not generate new attacks.

## Scope boundary

Every campaign must declare:

- target
- authorization basis
- allowed actions
- prohibited actions
- objective
- measurable success criteria
- disclosure requirements when applicable

Red Lab does not infer authorization and does not expand a campaign beyond the stored scope.

## v0.1 acceptance criteria

Red Lab v0.1 is functionally complete when it can:

1. preserve a complete attempt lineage;
2. keep proposals separate from executed evidence;
3. complete accepted drafts without duplicate attempts;
4. independently score apparent success;
5. require replay before confirmation;
6. calculate campaign metrics; and
7. produce a self-contained Markdown report.

The branch implements all seven criteria. Live provider calls still require the operator's API credentials and an authorized test target.
