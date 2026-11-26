# Background investigations

- Ingestion stores an alert and its triage decision in one transaction.
- Eligible alerts schedule individual jobs or join a matching pending group.
- Suppressed alerts remain stored without an automatic job.
- A grouped job analyzes a consistent snapshot of all retained group members.
- Group membership stops growing as soon as the representative job is claimed.
- Workers claim jobs using expiring leases and unique claim tokens.
- A heartbeat renews the lease during analysis.
- Report storage, job-result linking, and job completion share one transaction.
- Expired workers cannot finalize jobs.
- Retryable failures use bounded attempts and increasing delays.
- Ctrl+C finishes the current investigation before stopping.
- Processing may repeat after a crash; inference is not exactly once.
- Completed reports remain provisional and require analyst review.
- Manual checks have validated Wazuh delivery and the worker lifecycle.
  Real-model report accuracy remains a separate validation concern.

## Targeted investigations

Use `python -m cybertriage worker --once --job-id JOB_ID` to process one
specific eligible job. Omitting `--job-id` preserves normal queue selection.

Targeted selection applies to both claiming and attempt-exhaustion updates,
leaving other jobs queued. Lease ownership, retry availability, attempt limits,
and atomic completion still apply. A job that is completed, failed, waiting for
its retry delay, or owned under a valid lease is not eligible for processing.

## Opt-in read-only investigation

```powershell
python -m cybertriage worker --investigate --once --job-id JOB_ID
```

`--investigate` enables the bounded model/tool loop for eligible queued alerts.
Without the flag, the worker uses ordinary grounded analysis. The same mode is
available through `analyze-stored --investigate --record-id ALERT_RECORD_ID` for
an explicitly requested additional report without resetting a completed job.

Indexer settings and credentials are assembled before the worker claims jobs.
Use the existing environment or `.env.local` configuration. Non-interactive
workers require CYBERTRIAGE_INDEXER_PASSWORD; an interactive command can use the
hidden password prompt. No additional model is downloaded by this mode.

## Application-generated task

`ReadOnlyStoredInvestigationPlanner` implements the planner port. The stored-alert
use case asks it for a task and combined account/host authority before invoking analysis.
Raw log text, descriptions, and model prose never become task instructions.

For Windows Security 4624/4625 the planner selects the explicit target account
and domain. Other Windows Security events prefer a complete explicit initiating
account/domain, falling back to a complete target identity. Names do not establish
account type or operator identity. Domain aliases, missing identities, and
unstructured usernames are not guessed.

The permitted window spans observed member timestamps with five minutes of
padding on each side. It is not the grouping bucket duration. A group snapshot
includes every retained member when computing the span. Scope duration is capped
at 24 hours and each lookup at 10 results. Authentication-first objectives request
5 results; related-event objectives request 3.
The lookup uses indexed Wazuh alert timestamps and may return other hosts for the
same identity; results do not independently establish a common actor.

Missing or unsupported structured identities produce an empty account scope.
The report states missing context; an attempted authentication search is rejected
before reaching the Indexer. Explicit manager/agent metadata still permits
bounded related-event host context without guessing an account identity.

For account/group/process alerts, the planner requests the corresponding
`search_related_events` profile first. Other alerts can request general host
context, and authentication alerts retain their initial account lookup. The
related tool requires the exact originating manager and agent; it cannot silently
pivot across hosts. Mixed-host generated group snapshots are rejected. See
[related-event authority](related-events.md).

## Per-job authority and provenance

The composition root supplies an invocation-local tool factory. Every stored
investigation builds scoped tools without mutating shared model/tool state.
An authentication tool compares its validated request against the account/domain
set, time interval, and result limit before calling the searcher. Out-of-scope
requests produce an explicit outside_scope tool error without a backend lookup.
A scoped model invocation without a scoped factory fails rather than falling
back to unrestricted tools. Registered capabilities cannot change through scope.

The existing two-request budget, message/context limits, read-only transport,
lease heartbeat, stale-owner rejection, and atomic job/report completion remain.
Report results retain investigation_task, investigation_scope_json, and each
tool execution. Completion logs include the tool-call count. Empty scopes and
model responses without tool calls remain visible in the saved provenance.

## Analyst-requested investigations

`requested_investigations` is a separate leased queue for explicit additional
investigations. It preserves automatic jobs and previous results and retains
the requesting actor, task, case version and idempotency key. Its fixed adapter
table identifiers share the lease/retry/heartbeat and atomic completion code;
no HTTP/config value controls SQL table names. Identity fields are immutable.

The request worker rechecks an open case and active anchor membership, then adds
the bounded analyst objective to the application-generated plan. It cannot
expand tool authority. Results use the same exact input coverage and case report
linking transaction. The authenticated API queues work and returns status/report
IDs instead of performing model inference in an HTTP request. These additional
queue paths and the shared-table refactor require regression validation.

Combined authority snapshots use version 2 and add `related_events`; their
authentication account fields retain the existing contract. Previously saved
version-1 snapshots remain readable without rewriting reports.

The model cannot label feedback, suppress alerts, approve response actions, or
execute commands through these tools. Reports remain provisional; scope checks
bound queries but do not certify the model's interpretation of returned evidence.
