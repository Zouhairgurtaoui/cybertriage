# Implementation status

## Current development baseline

The selected local model is `qwen3:4b-instruct`. Thinking is disabled in its
client configuration. Reports are provisional and require analyst review.
The model port supports alternative model adapters.

Implemented code paths:

- MITRE ingestion pinned by a revision in `config/sources.yaml`.
- Configurable Microsoft documentation ingestion, chunking and Chroma storage.
- Hybrid semantic/BM25 retrieval across enabled collections, exact identifier
  prioritization, explicit platform filtering, document diversity and whole-chunk
  citations with persisted query-local ranking provenance.
- Metadata-only refresh for existing Chroma chunks, latest-fetched snapshot
  selection and a retrieval inspection CLI without chat-model generation.
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
- Related-event Indexer search and model tool with explicit manager/agent/time
  authority, account/group/process profiles, generic host context, exact optional
  filters, bounded field projections and source provenance.
- Stored-alert family-aware planning and combined version-2 account/host scopes;
  both read-only tools are registered without changing the two-request budget.
- Opt-in scoped background/stored-alert investigation with application-generated
  tasks and persisted query authority and tool execution records.
- Computed authentication search summaries and sourced status-code definitions.
- Revisioned pre-analysis triage with retained suppressed alerts and audit history.
- Bounded candidate groups that share pending jobs and supply full member summaries.
- Append-only analyst labels, explicit release, and per-policy suppression metrics.
- Persistent operator-managed cases with alert/group-snapshot attachments,
  soft detachment, notes, timelines, explicit disposition and versioned updates.
- Evidence-checked observed relationships, separately retained hypotheses and
  append-only reviews; accepting a hypothesis does not change its kind.
- Automatic transactional report linking with exact input-alert coverage and
  bounded legacy report backfill on attachment.

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

- Automatic cross-technique case correlation and Neo4j/Cyber Kill Chain projection.
- Live scoped-worker validation and additional investigation tools.
- Labelled retrieval relevance evaluation and controlled, cached live web retrieval.
- Real-model grounding/report-quality evaluation and operational workload validation.
- Authenticated analyst review, stored approvals and audit records.
- Allowlisted response executors connected to the response policy.
- API endpoints for the future analyst web application.
- Deployment configuration and documentation.

The policy foundation does not imply the approval/execution workflow is complete.
Local case findings are stored, but authenticated approvals and executors are
not yet connected. See [case architecture](architecture/cases.md).

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

The case validation harness (`scripts/validate_cases.py`) covers persistent
lifecycle, concurrency, relationship provenance, exact report coverage,
transaction rollback, pagination and history constraints with isolated fixtures.
It has been added but has not yet been executed. The scoped worker extension
to the boundary suite also remains pending execution; the recorded 29-check
result does not include either extension.

`scripts/validate_related_events.py` adds 16 isolated check groups for request
and runtime authority, query construction, source mapping, role preservation,
projection/truncation, tool errors and budgets, invocation isolation and persisted
worker tool provenance. They have not yet been executed. Live Indexer mappings
and model selection/interpretation of the new capability remain unvalidated.

`scripts/validate_retrieval.py` adds 17 offline check groups for hybrid ranking,
platform/identifier boundaries, corpus lifecycle, budgets, source errors,
concurrent provenance, metadata upgrades and analysis compatibility. They have
not yet been executed. Real-query relevance and model grounding gains have not
yet been measured. Existing collections need source refresh to gain explicit
platform metadata; finish ingestion and restart analysis before using that corpus.

