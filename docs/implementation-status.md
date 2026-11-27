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
- Identifier-based live Microsoft/MITRE augmentation with fixed vendor routes,
  public-IP-pinned TLS, bounded requests/articles, TTL/conditional/negative caching,
  refresh leases/backoff, and per-reference freshness provenance.
- Offline knowledge overrides for retrieval, direct analysis, stored alerts and
  workers; public lookup failures remain visible while local context is retained.
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
- Deterministic case graph JSON export and optional version-checked, transactional
  Neo4j publication with namespace/case isolation and explicit schema setup.
- Evidence-backed operator Kill Chain assessments, append-only reviews and
  unassessed stages; hypotheses and reported chronology retain their meanings.
- Incremental Neo4j delivery worker with durable per-namespace case-version cursors.
- Bounded retained-alert correlation candidates with explicit host/account roles,
  evidence hashes and time distances; no automatic attachment or causal findings.
- Persisted response proposals, reviews, approval expiry, version/evidence/policy
  bindings, at-most-one dispatch claims, outcomes and explicit reconciliation.
- Vendor-independent firewall gateway/executor contracts and an OPNsense external
  alias adapter, with application-managed block leases and an expiry worker.
- A separate analyst API with hashed expiring credentials, explicit operation/case
  permissions, authenticated audit actors, bounded request bodies and OpenAPI.
- A separate leased queue and worker for explicit analyst-requested investigations.
- Root Docker Compose lifecycle for frontend, APIs and workers with an external
  model-service endpoint; optional local Neo4j/schema/publication services, private API TLS,
  file credentials, process health, retained named volumes and explicit import.
- An independent React analyst application with evidence/case queues, timeline,
  reports, investigation requests, relationship/Kill Chain review, graph browsing,
  response approvals/dispatch and triage evaluation. Vite and Nginx provide
  same-origin API proxies; frontend dependencies and deployment remain separate.

## What the YAML files actually control

`sources.yaml` is loaded for ingestion, analysis assembly and catalogue updates.
It controls source enablement, MITRE revision, collection names, Microsoft pages
and URLs, and chunk size/overlap.

`response_actions.yaml` is loaded for response preview and persisted workflows. It controls
execution enablement, action rules, targets, required parameters, duration,
protected networks, and approval lifetime. Execution is disabled by default.
The preview never invokes an executor. OPNsense execution requires an explicitly
configured named target in firewall configuration and an approved stored proposal.
`firewalls.yaml` ships with no targets; deployment-specific `.local.yaml` variants
are ignored. Analyst credentials likewise require explicit local provisioning.

`triage.yaml` is loaded by ingestion for scheduling decisions. Its revision and
settings snapshot are retained with the audit trail. The authentication code
registry is loaded by model/tool composition and stored-alert worker composition;
it supplies documented definitions without a live network fetch.

## Report contract

Analysis produces readable text with references and catalogue definitions.
Generation checks reject empty or unfinished output. Reports require review
for factual accuracy and citation relevance. Optional JSON report files store
application data; the model is not required to generate JSON.

## Remaining work

- Labelled evaluation of correlation candidates and any future causal/automatic
  case assignment; the implemented candidate query does not establish an attack chain.
- React dependency installation, locked build and browser/API acceptance,
  including accessibility, graph interaction, authorization and mutation recovery.
- Identity-provider/browser-session integration beyond in-memory API-token entry.
- Live scoped-worker validation and additional investigation tools.
- Labelled retrieval relevance evaluation, live source compatibility/workload
  validation, and additional source providers/discovery strategies.
- Real-model grounding/report-quality evaluation and operational workload validation.
- Live analyst API authorization and requested-investigation queue regression.
- OPNsense API/version, rule placement, traffic effects, expiry and failure-recovery
  acceptance. FortiGate/pfSense concrete adapters are not implemented.
- Operational deployment acceptance, backup/restore and monitoring verification.
- Container image builds, data import, Windows/VM connectivity, worker shutdown
  and full-stack acceptance for the Compose layout.

The core response and analyst backend paths are implemented, with execution
disabled by default. This is not a claim of runtime or production acceptance.
See [response architecture](architecture/response-workflow.md),
[analyst API](architecture/analyst-api.md) and [operations](operations.md).

The triage policy ships with no active suppression rules. Unknown alerts remain
eligible for analysis. Existing queue contents are not retroactively filtered.
Operator CLI actor identifiers remain asserted metadata. Analyst HTTP operations
use authenticated API principals. The React application holds API credentials
only in memory; password login and identity-provider sessions remain unimplemented.



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

`scripts/validate_live_web.py` adds 22 offline check groups for public route and
privacy boundaries, DNS/TLS/HTTP handling, article parsing, cache freshness and
leases, backoff, quotas/rollback, reference selection and configuration. They
have been provided for offline validation; a complete execution result is not
recorded here. A live lookup retrieved Microsoft event 4725 and MITRE T1098.007
with one HTTP attempt each; repeating those lookups used fresh cache entries
with zero HTTP attempts. This validates those routes and cache reuse only.
Broader vendor compatibility, live worker integration and retrieval/model-quality
gains still require measurement.

`scripts/validate_case_graph.py` adds 12 isolated graph check groups using SQLite
fixtures and a scripted Neo4j substitute. They have not been executed. Real
Neo4j schema/query compatibility, concurrency and publication remain unvalidated;
the offline substitute does not parse Cypher. End-to-end live investigation and
case validation remain pending.

The response workflow, OPNsense gateway, expiry worker, analyst API, requested
investigation queue, candidate query and incremental graph delivery have received
syntax/import/CLI checks only. Their functional, concurrency, live-device and
regression acceptance remains pending. The historical 29-check result does not
cover these changes. Reinforcement-learning model training is not implemented.

The React source and local module imports received static parsing checks.
The frontend lockfile is present and consumed by Docker builds. No complete
bundle/browser or container acceptance result is recorded yet. Static checks do
not certify visual quality, runtime integration or deployment security.


## Agent report access and launchers

The React console has a dedicated Saved reports page for saved automatic and
requested reports, with alert-coverage filtering and direct inbox links. Full
reports retain global scope and `reports:read_all` authorization. Case reports
use the same viewer and appear before follow-up requests.

Linux and Windows launchers support explicit knowledge preparation as well as
existing-data import. Initial configuration creates a review credential only
when its local file is absent. Linux workers use a host-network override for
local model and Indexer dependencies. Runtime/browser/Linux acceptance of these
changes remains pending. Obsolete root learning helpers are excluded from the
active application; validation tools remain available.

## Persistent case conversations

Case chat adds retained analyst messages, frozen case/history context and
provisional replies with provenance. A separate leased worker supports bounded
retries and rejects stale completions. Alert-backed replies join saved analysis
coverage; case-only replies stay in the conversation without fabricated alerts.
Review mode disables tools. Investigation mode uses existing derived query
scopes. The React thread, sidebar history and source viewer are implemented;
functional concurrency, browser and live-model acceptance remains pending.

## Password sessions and local generation scheduling

Username/password login, fixed-cost scrypt hashes, persistent login throttling,
15-minute revocable sessions and the existing API-token method are implemented.
Local provisioning retains the principal's current permissions and case scope.
Model reads default to 600 seconds with a separate short connection timeout;
shared local generation scheduling prevents concurrent generation by this stack.
Chat timeouts are terminal for the turn, with technical diagnostics in worker
logs. Authentication security, browser sign-out and renewed live generation
acceptance remain pending; static checks do not establish runtime correctness.

## Conversation latency diagnostics

Conversation prompts are shorter and retrieve two knowledge chunks while
retaining exact event definitions. Their disclosed alert projection omits raw
log JSON only when it repeats the decoded payload. Source alerts remain retained unchanged.
Server logs record model completion/timing metadata and distinguish unfinished
output, malformed responses and context limits. Incomplete or oversized output
is rejected without repeatedly generating the same failed chat turn. Runtime
latency improvements and successful live-case completion remain unmeasured.
