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
- Authenticated Wazuh ingestion and integrity-checked SQLite alert storage.
- Leased background jobs with heartbeat, retries, and atomic report completion.
- Opt-in CLI investigation with a bounded read-only authentication tool.
- Computed authentication search summaries and sourced status-code definitions.
- Revisioned pre-analysis triage with retained suppressed alerts and audit history.
- Bounded candidate groups that share pending jobs and supply full member summaries.
- Append-only analyst labels, explicit release, and per-policy suppression metrics.

## What the YAML files actually control

`sources.yaml` is loaded for ingestion, analysis assembly and catalogue updates.
It controls source enablement, MITRE revision, collection names, Microsoft pages
and URLs, and chunk size/overlap.

`response_actions.yaml` is loaded for response-policy preview. It controls
execution enablement, action rules, targets, required parameters, duration,
protected networks, and approval lifetime. Execution is disabled by default.
No actual firewall executor is implemented or invoked by the preview.

`triage.yaml` is loaded by ingestion for scheduling decisions. Its revision and
settings snapshot are retained with the audit trail. The authentication code
registry is loaded by model/tool composition and stored-alert worker composition;
it supplies documented definitions without a live network fetch.

## Report contract

Analysis produces readable text with references and catalogue definitions.
Generation checks reject empty or unfinished output. Reports require review
for factual accuracy and citation relevance. Optional JSON report files store
application data; the model is not required to generate JSON.

## Remaining backend work

- Cross-technique incident/case correlation and Neo4j projection.
- Background-worker tool-calling integration and additional investigation tools.
- Real-model grounding/report-quality evaluation and operational workload validation.
- Authenticated analyst review, stored approvals and audit records.
- Allowlisted response executors connected to the response policy.
- API endpoints for the future analyst web application.
- Deployment configuration and documentation.

The policy foundation does not imply the approval/execution workflow is complete.

The triage policy ships with no active suppression rules. Unknown alerts remain
eligible for analysis. Existing queue contents are not retroactively filtered.
Operator CLI actor identifiers are asserted metadata; authenticated analyst
sessions and authorization are required before exposing review through a web API.



## Evaluation

Controlled validation covered duplicate-safe grouping, a completed grouped
worker report with sourced definitions for both members, suppression scope and
expiry, severity/protected-event overrides, append-only feedback, release, and
evaluation of a deliberately unsafe suppression. These results and remaining
coverage are recorded in [triage validation](validation/triage.md).

The isolated boundary/regression harness subsequently passed all 29 grouped
checks, covering concurrency, transaction rollback, audit enforcement, HTTP
ingestion responses, evaluation edge cases, grounding/tool budgets, and model
orchestration with scripted substitutes. This is separate from live model
accuracy and deployment validation.

The report recorder stores generated outputs under ignored `data/evaluations/`.
Execution completion and semantic review are tracked separately. Review criteria
and recorder usage are documented in [analysis evaluation](evaluation.md).

