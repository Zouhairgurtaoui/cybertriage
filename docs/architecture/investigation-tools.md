# Investigation tools

The first tool searches Windows Security logon events:
4624 for successful logons and 4625 for failed logons.

Requests identify an account and domain, an explicit time window
of at most 24 hours, and a result limit of at most 100.

The Wazuh Indexer adapter controls the endpoint, index scope,
authentication, and query construction.

Results preserve source identifiers and state coverage limits.
Empty results do not establish an absence of activity.
Truncated results must be identified.
Incomplete backend searches must raise an error.

## Query construction

The query builder selects Windows Security events 4624 and 4625,
filtered by target account, domain, and Wazuh alert timestamp.

The time interval includes its start and excludes its end.
Results are ordered by timestamp and restricted to selected fields.

One additional result is requested to detect truncation.
Account and domain filters use exact indexed values.
Field mappings require verification against the deployed Indexer.

## Indexer HTTP transport

The HTTP client uses a configured HTTPS origin, a trusted CA bundle,
and dedicated read-only Indexer credentials.

Searches are restricted to wazuh-alerts-*.
Redirects and implicit environment authentication/proxies are disabled.

Responses are limited to 2 MiB. Timed-out, early-terminated,
failed-shard, malformed, or oversized responses raise a search error.

Connection and read-inactivity timeouts are configured.
These are not a total wall-clock deadline.

## Authentication result mapping

The mapper validates event identity, target account, domain,
and the requested timestamp window.

Results preserve source identifiers and normalize timestamps to UTC.
Missing optional fields are represented as null.

The query requests status, subStatus, and failureReason from Windows
event data. The mapper exposes them as status_code, substatus_code,
and failure_reason using the existing bounded optional-text validation.
String values are preserved without interpretation; resource tokens
such as %%2310 remain source evidence rather than decoded explanations.
The CLI includes these fields through dataclass serialization.

Identical source-alert duplicates are collapsed.
Conflicting duplicates, malformed events, and out-of-scope events
raise InvestigationSearchError.

has_more indicates that the backend returned more matching documents
than the requested event limit. Duplicate collapsing may reduce
the number of distinct returned events.

## Shared transport

WazuhIndexerHttpClient accepts queries built by trusted application adapters
and executes bounded searches against wazuh-alerts-* through search_alerts.
Query size must match max_hits, which is limited to 1-101 documents. The extra
document lets capability-specific adapters detect truncation.

The HTTP transport owns HTTPS, authentication, response limits, timeouts,
and complete-search validation. Each investigation adapter owns its query
builder and result mapper. Shared JSON value types live in json_types.py.

The generic transport is internal and is not exposed as an agent tool.
Agent-facing operations accept validated investigation arguments.

## Connection configuration and CLI

The search CLI uses CYBERTRIAGE_INDEXER_URL, CYBERTRIAGE_INDEXER_USERNAME,
and CYBERTRIAGE_INDEXER_CA_BUNDLE for connection settings. The CA bundle must
be an existing absolute path on the machine running CyberTriage.

The password comes from CYBERTRIAGE_INDEXER_PASSWORD or a hidden interactive
prompt. It is excluded from the typed settings and search result payloads.

Use `python -m cybertriage search-authentication --help` for command usage.

## Current status

Shared transport, typed authentication mapping, environment configuration,
and the CLI are implemented. Live searches retrieved both
successful and failed Windows authentication events for a known account
on WS01 through the configured HTTPS connection and reader credentials.

Failure details are included in the query and result mapping. A live failed-logon
search verified preservation of status_code, substatus_code, and failure_reason.
The analysis CLI supports opt-in investigation; live tool-calling validation
and background-worker investigation integration remain pending.
The searches do not independently verify that write operations are denied.

## Live validation — 2026-11-25

The CLI retrieved nine matching Windows Security 4624 alerts
for a known CORP account on WS01.

Search window: 2026-09-01 17:00–17:30 UTC.
Requested limit: 10. Returned has_more: false.

Verified:
- HTTPS connection and authentication.
- Account, domain, event-type, and time filtering for this sample.
- Typed results with source identifiers and UTC timestamps.

The CLI also retrieved one matching Windows Security 4625 alert for
the same account on WS01, in the interval 2026-09-01 02:24:50–02:25:00 UTC.
The result preserved Windows record ID 8873, source IP 127.0.0.1,
logon type 2, and a null target logon session ID. Returned has_more: false.

A subsequent search of the same event returned status_code 0xc000006e,
substatus_code 0xc0000072, and failure_reason %%2310, matching the source fields.
Live tool-calling validation remains pending.
Retrieved logons do not independently establish malicious activity.
## LangChain authentication tool

The search_authentication tool adapts AuthenticationEventSearcher through
a typed input schema. It accepts an account, domain, timezone-aware time
window of at most 24 hours, and a result limit of 1–10.

Results preserve source identifiers, failure details, coverage, and
truncation metadata. Responses are limited to 12,000 UTF-8 bytes.
Oversized responses and unsuccessful searches produce explicit errors.

The adapter receives its search implementation through dependency
injection. Credentials and query construction remain inside the Indexer
adapters. Model binding and investigation-loop orchestration are separate
components.
## Model investigation loop

OllamaInvestigationModel implements the InvestigationModel port.
It maintains a separate conversation for each investigation and exposes
only explicitly registered tools.

An investigation permits at most two tool requests and three model
responses. Duplicate requests are rejected without repeating the search.
Tool results are returned through messages linked to their call IDs.

After the tool budget is exhausted, the final model request omits tool
definitions. Empty, unfinished, malformed, or over-budget responses fail
without accepting a partial report.

The result contains report text and structured tool execution records.
Conversation size is bounded by a serialized-byte limit, which does not
represent an exact token count.

## Analysis integration

`analyze --investigate` enables the bounded investigation model.
Without this flag, analysis uses the ordinary triage model.

Investigation requires an explicit analyst task supplied through --task.
The CLI validates the task before constructing analysis dependencies.
The application and model adapter use the same task validator: nonempty text,
at most 4,000 UTF-8 bytes, with unsupported control characters rejected.
Supplying --task without --investigate is an input error.

The task is passed as a separate analyst message rather than embedded in
incident evidence. Evidence, reference excerpts, and tool outputs remain
untrusted data. Task parameters describe requested checks, not observed facts.
The investigation prompt requests explicit, valid analyst searches before
report generation; this instruction does not guarantee model compliance.

Knowledge retrieval and event catalogue lookup run before model analysis.
The composition root registers the authentication search tool and provides
its configured Indexer client.

Saved results include investigation_task and tool_executions alongside report
text and references. Ordinary analysis stores a null investigation_task.
Each execution records its call ID, tool name, arguments, result, and status.
An empty execution list means no tool calls were recorded.

The CLI prints tool execution names, statuses, and call IDs. Detailed records
are included in the JSON report selected with --output. Existing JSON report
storage serializes these records without a database schema migration.

Background-worker investigation integration and live tool-calling validation
remain pending. Background workers continue to use ordinary analysis.
