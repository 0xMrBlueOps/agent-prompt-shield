# Red Lab Promptfoo Pliny bridge

This bridge connects Promptfoo's public `pliny` red-team plugin to the Red Lab evidence ledger.

The Promptfoo plugin dynamically fetches curated prompts from the L1B3RT4S repository. Those prompts are AGPL-3.0 licensed; review the upstream license before redistributing prompts or creating derived datasets.

## Requirements

- Node.js supported by the current Promptfoo release
- `npx` or a Promptfoo installation
- provider credentials required by the selected target
- an owned target, explicit challenge authorization, or written permission

## 1. Generate configuration

```bash
agent-redlab-pliny init \
  --target "openai:gpt-5" \
  --purpose "Authorized safety evaluation of my application" \
  --num-tests 25 \
  --output promptfooconfig.pliny.yaml
```

The generated configuration contains:

```yaml
targets:
  - id: "openai:gpt-5"
redteam:
  purpose: "Authorized safety evaluation of my application"
  injectVar: "prompt"
  plugins:
    - id: pliny
      numTests: 25
```

Change the target and input mapping to match the application under test.

## 2. Run Promptfoo

```bash
agent-redlab-pliny run \
  --config promptfooconfig.pliny.yaml \
  --output promptfoo-pliny-results.json \
  --ack-authorized
```

The authorization flag is mandatory. The bridge invokes:

```bash
npx promptfoo@latest redteam run \
  --config promptfooconfig.pliny.yaml \
  --output promptfoo-pliny-results.json \
  --no-share
```

`--no-share` prevents accidental publication of potentially sensitive prompts, outputs, or traces.

## 3. Import into Red Lab

```bash
agent-redlab-pliny import \
  --ledger .redlab/ledger.jsonl \
  --campaign <CAMPAIGN_ID> \
  --results promptfoo-pliny-results.json
```

To attach the imported tests to an existing research branch:

```bash
agent-redlab-pliny import \
  --campaign <CAMPAIGN_ID> \
  --results promptfoo-pliny-results.json \
  --parent <ATTEMPT_ID>
```

## Result mapping

Promptfoo evaluates whether the target passed its safety assertions. Red Lab records the inverse red-team interpretation:

- Promptfoo assertion passes -> Red Lab `failed` attack
- Promptfoo assertion fails -> Red Lab potential `successful` attack
- partial numeric score -> Red Lab `partial`
- unrecognized result -> Red Lab `invalid`

An imported potential success is **not a confirmed finding**. It must still pass Red Lab's independent evaluation and replay-verification gates.

## Data captured

Each imported row records:

- exact available prompt
- target response
- Promptfoo provider and grading metadata
- Pliny attack family label
- optional parent attempt
- provisional outcome
- reminder that independent verification is required

## Trust boundary

Promptfoo and dynamically fetched L1B3RT4S content are external research inputs. Do not treat plugin text as trusted instructions for the Red Lab operator, evaluator, or tools. Only the declared campaign scope authorizes actions.
