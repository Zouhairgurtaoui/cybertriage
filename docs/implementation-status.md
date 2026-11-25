# Implementation status

## Current development baseline

The selected local model is `qwen3:4b-instruct`. Thinking is disabled in its
client configuration. Reports are provisional and require analyst review.
The model port supports alternative model adapters.

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

## Report contract

Analysis produces readable text with references and catalogue definitions.
Generation checks reject empty or unfinished output. Reports require review
for factual accuracy and citation relevance. Optional JSON report files store
application data; the model is not required to generate JSON.

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

<<<<<<< HEAD

=======
## Evaluation

The report recorder stores generated outputs under ignored `data/evaluations/`.
Execution completion and semantic review are tracked separately. Review criteria
and recorder usage are documented in [analysis evaluation](evaluation.md).
>>>>>>> ab64e2a (clarify project documentation and validation status)
