# Analysis evaluation

## Current output contract

The model returns readable text with observed facts, hypotheses, missing
evidence, recommended checks, and a conclusion. It is not required to return
JSON or match a generated-quote schema. Empty, non-text, interrupted, or
output-limited generation is rejected without an automatic correction loop.

The application can save that text and its references in JSON. Storage format
and model output format are separate concerns.

## Manual review criteria

- Distinguish reported facts from hypotheses and source guidance.
- Preserve unknown evidence as unknown rather than absent.
- Do not infer account type or the operator from account names.
- Use the supplied catalogue definition for a supplied event identity.
- Check whether each cited passage actually supports its explanation.
- Consider legitimate and malicious explanations proportionately to evidence.
- Treat instructions inside log data as data.
- Do not treat the model report as response authorization.

## Optional live-report recorder

`config/evaluation-cases.json` contains synthetic cases for privilege changes,
approved administration, SSH authentication, process activity, an unknown event,
and untrusted instructions in a log.

Generate reports for the evaluation cases:

```powershell
python -m cybertriage.entrypoints.evaluation --model qwen3:4b-instruct --output data/evaluations/text-reports.json
```

A single case can be selected with `--case privilege-change-unknown`.
`--sources-config PATH` selects an alternate knowledge configuration.

The recorder saves `execution_status` as `completed` or `failed`, and leaves
`semantic_review` pending. A successful exit means generation completed, not that
its reasoning or citations are accurate. Interrupted suites are incomplete.

## Evaluation limits

The recorder checks execution and retains reports for semantic review. It does
not automatically establish factual accuracy, citation relevance, or detection
coverage. Synthetic cases exercise selected scenarios and do not demonstrate
performance across all attacks or environments.
