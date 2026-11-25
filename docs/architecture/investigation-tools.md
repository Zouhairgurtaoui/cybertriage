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