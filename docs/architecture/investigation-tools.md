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

Current status: contract defined; adapter and agent integration pending.
## Query construction

The query builder selects Windows Security events 4624 and 4625,
filtered by target account, domain, and Wazuh alert timestamp.

The time interval includes its start and excludes its end.
Results are ordered by timestamp and restricted to selected fields.

One additional result is requested to detect truncation.
Account and domain filters use exact indexed values.
Field mappings require verification against the deployed Indexer.

Current status: contract and query builder implemented;
HTTP adapter, live validation, and agent integration pending.
## Indexer HTTP transport

The HTTP client uses a configured HTTPS origin, a trusted CA bundle,
and dedicated read-only Indexer credentials.

Searches are restricted to wazuh-alerts-*.
Redirects and implicit environment authentication/proxies are disabled.

Responses are limited to 2 MiB. Timed-out, early-terminated,
failed-shard, malformed, or oversized responses raise a search error.

Connection and read-inactivity timeouts are configured.
These are not a total wall-clock deadline.

Current status: HTTP transport implemented; event mapping,
connection configuration, live validation, and agent integration pending.
## Authentication result mapping

The mapper validates event identity, target account, domain,
and the requested timestamp window.

Results preserve source identifiers and normalize timestamps to UTC.
Missing optional fields are represented as null.

Identical source-alert duplicates are collapsed.
Conflicting duplicates, malformed events, and out-of-scope events
raise InvestigationSearchError.

has_more indicates that the backend returned more matching documents
than the requested event limit. Duplicate collapsing may reduce
the number of distinct returned events.

Current status: search adapter implemented;
connection configuration, CLI, live validation, and agent integration pending.