# Implementation status

## Current development baseline

The selected local model is `qwen3:4b-instruct`. Thinking is disabled in its
client configuration. Its readable output is accepted provisionally for
continuing backend development; accuracy improvements can be revisited later
with a stronger local model or another model adapter.

Implemented code paths:

- MITRE ingestion pinned by a revision in `config/sources.yaml`.
- Configurable Microsoft documentation ingestion, chunking and Chroma storage.
- Source-aware retrieval from the configured enabled collections.
- Local Windows Security catalogue with exact provider/channel/event-ID lookup.
- Validated local catalogue snapshots and atomic replacement.
- Five-section text analysis through a small model port.
- Input size bounds, normal-completion checks, and explicit generation failures.
- Optional application JSON storage of report text, definitions and references.
- Response-policy configuration, typed proposals/approvals, and policy preview.
- IP-block parameter validation, target allowlisting and approval fingerprinting.

## What the YAML files actually control

`sources.yaml` is loaded for ingestion, analysis assembly and catalogue updates.
It controls source enablement, MITRE revision, collection names, Microsoft pages
and URLs, and chunk size/overlap.

`response_actions.yaml` is loaded for response-policy preview. It controls
execution enablement, action rules, targets, required parameters, duration,
protected networks, and approval lifetime. Execution is disabled by default.
No actual firewall executor is implemented or invoked by the preview.

## Simplification decision

The experimental constrained-JSON analysis path was removed from runtime:
structured draft classes, quote-copy enforcement, account pseudonyms, lexical
rejection rules, and automatic repair are no longer used. They added brittleness
without establishing reliable semantic correctness.

References and catalogue definitions remain. Model prose still requires review;
there is no claim that the report is mechanically proven accurate. The optional
JSON report file is application storage, not a required model-output format.

## Remaining backend work

- Wazuh alert normalization and authenticated, size-limited ingestion.
- Durable alert/report/case storage and idempotency.
- Time-bounded related-alert lookup with explicit correlation uncertainty.
- Bounded investigation tools and workflow orchestration.
- Authenticated analyst review, stored approvals and audit records.
- Allowlisted response executors connected to the response policy.
- API endpoints for the future analyst web application.
- Deployment configuration and documentation.

The policy foundation does not imply the approval/execution workflow is complete.

## Testing

Testing is owned by the project owner. The current coding-only changes have not
been exercised after that instruction. Earlier experimental outputs remain under
ignored `data/evaluations/`; they are historical results, not certification of
this implementation.
