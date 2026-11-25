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
Agent integration remains pending.
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
Agent integration remains pending.
Retrieved logons do not independently establish malicious activity.
