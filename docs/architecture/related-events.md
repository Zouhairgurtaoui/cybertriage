# Related-event investigation

`search_related_events` retrieves candidate context from indexed Wazuh alerts.
It complements `search_authentication`, which remains a target-account search
for Windows Security 4624/4625. The new tool supports account and group changes,
process activity, and general host alerts without turning temporal proximity
into a finding of compromise.

## Components

`RelatedEventSearchRequest` and `RelatedEventScope` validate domain inputs.
`RelatedEventSearcher` is the application port. `WazuhRelatedEventSearcher`
uses a query builder and response mapper behind the shared HTTPS Indexer
client. The LangChain adapter validates model arguments and enforces authority
before calling the port. The operator CLI calls the same search port directly.

Query profiles live in the application policy layer; neither domain requests
nor application ports depend on LangChain, requests or OpenSearch query syntax.
`related_event_summary` computes counts, actual filters, duration and projection
limits independently of the model. Additional backends can implement the port
without changing the model tool or worker.

## Required scope and optional filters

Every query requires the exact `source_instance` (Wazuh manager name), `agent_id`,
and a positive timezone-aware interval of at most 24 hours. The interval includes
its start and excludes its end. Queries use Wazuh alert `timestamp`; reported
Windows `systemTime`, where present, is returned separately.

There is no model-supplied Indexer URL, index name, query DSL, wildcard operation,
script, shell command, or write endpoint. Host and timestamp filters cannot be
removed through tool arguments. The query profiles are finite provider/channel/
event-ID combinations, not event-ID matches across unrelated providers.

| Family | Filter |
| --- | --- |
| `all` | All visible alerts on the requested manager/agent in the interval, including non-Windows alerts. |
| `authentication` | Windows Security 4624 and 4625. |
| `account_changes` | Windows Security 4720, 4722–4726, 4738, 4740–4743, 4767 and 4781. |
| `group_changes` | Windows Security 4727–4735, 4737, 4754–4758 and 4764. |
| `process_activity` | Windows Security 4688/4689 and Sysmon Operational 1/5. |

These profiles define search coverage, not attack classifications. An event
outside a profile remains unsearched. The general `all` profile can retrieve
other alert types without assigning them an invented event definition. The
current adapter targets the `manager`, `agent` and `data.win` Wazuh alert fields
used by the lab's 4.x indices; changed field mappings require adapter validation.

Optional filters combine with AND:

- Account/domain: exact target pair, exact initiating pair, or an exact reported
  Sysmon user string in `domain\account` form. Name and domain cannot come from
  different roles. No domain aliases or account SIDs are inferred.
- Source IP: `data.srcip`, Windows `ipAddress` or Sysmon `sourceIp`. Destination
  IP fields do not satisfy a source-IP filter. Common canonical, expanded and
  IPv4-mapped representations are included in literal term queries; arbitrary
  indexed textual variants are not guaranteed to match. Zone IDs are rejected.
- Process GUID: literal reported current/parent/source/target process GUID
  fields. The tool does not substitute a process ID or infer a process tree.
- Logon ID: literal reported target, subject or Sysmon logon-ID fields. The
  response preserves the matched field's role; a subject session is not the
  failed target's session. Zero session IDs are rejected.

For group-change events, the target account fields can identify the group;
`memberName` and `memberSid` identify the affected member separately. Applying
an account-name filter is not a complete group-membership search for that user.
The stored planner starts these searches without a guessed account filter.

## Runtime authority

`InvestigationScope` extends the existing authentication scope with a separate
host-scoped authority. Existing authentication authorization and its `allows`
contract remain unchanged. The combined version-2 snapshot retains the account
fields and adds `related_events` with permitted manager/agent pairs, times,
families and result limit. Existing version-1 report snapshots remain readable.

The stored-alert planner derives the host from normalized alert metadata and
the interval from input alert/group timestamps plus the existing five-minute
padding. Mixed-manager or mixed-agent group snapshots are rejected. Source log
text, descriptions and model prose do not select authority or become tasks.

Account/group/process alerts request the corresponding related-event family
first, with a limit of three. A separate authentication lookup can investigate
the explicit initiating/target account within the existing account scope.
Authentication alerts retain their initial authentication lookup, with related
host context available for a second request. Alerts without a complete supported
account identity can still request host context; authentication search stays
disabled for them.

Each invocation builds its own scoped tool instances. The related-event tool
rejects a missing scope or a different manager, agent, interval, family or result
limit before the Indexer is called. Additional filters can narrow a permitted
host query; they cannot authorize another host. Automatic cross-host pivots
remain outside this capability. The existing authentication tool's explicit
account search can still return other visible hosts for that account.

File-based `analyze --investigate` requires explicit `--source-instance`,
`--agent-id`, `--start` and `--end` to authorize related-event calls. Optional
`--account` and `--domain` also authorize authentication calls in this combined
scope. Without those host flags, legacy analyst-directed authentication remains
available, but related-event calls fail with `scope_required`.

## Result integrity, projection and budgets

The shared HTTP client retains verified TLS, read-only credentials, disabled
redirects/implicit proxies, response limits, and rejection of partial searches.
Results are sorted oldest first. One additional hit detects omitted results.

The mapper revalidates manager, agent, interval, family and optional filters on
every returned hit, including the lookahead. An out-of-scope or malformed hit
fails the search; it is not silently discarded. Identical source IDs collapse
only if the selected source data agrees. Conflicting duplicates fail visibly.

Each event preserves manager/source alert ID, Indexer index/document ID, UTC
timestamp, agent, rule metadata, provider/channel/event identity when present,
and selected fields with their original paths. A SHA-256 hash describes the
selected Indexer source projection, not a full original log or a signature of
external origin. General non-Windows alerts have no fabricated Windows identity.

Selected detail values have a combined 3,000-byte budget per event. Individual
values are capped at 512 bytes, or 1,024 bytes for command lines. Clipped values
carry `truncated`; values omitted by the projection budget are listed separately.
Raw log bodies are not selected. Command lines and other returned content remain
untrusted evidence and can contain sensitive operational data.

The computed summary records the actual interval, host and filters, searched
event identities, returned counts, `has_more`, field projection limits and
coverage. Local catalogue definitions are supplied when available; otherwise
event meanings and status/resource-token meanings remain unresolved. Definitions
describe event types and do not establish malicious intent.

The CLI accepts 1–100 results. Model calls accept 1–10 (default three), with a
12,000-byte serialized result budget. Excess output becomes `result_too_large`
with a request to narrow the search; it is not accepted as a successful partial
result. The existing two-request investigation budget and 32,000-byte context
budget remain unchanged. Source failures remain errors, never empty successes.

## Persistence and coverage

The worker and stored-alert paths register both tools. They preserve the
application-selected task, combined authority snapshot, and every tool call's
arguments, outcome and result in the saved report. The existing atomic
report/job completion and case-report linking apply to these reports.

Search hits do not automatically become stored alert attachments, observed
case relationships, suppression decisions or response approvals. Their source
IDs are investigation evidence available in the report. Candidate context alone
does not confirm a common actor, causal sequence or attack stage.

Only indexed alert documents visible to the configured reader are searched.
This is not raw Windows event-log or Wazuh archive retrieval. Alerting thresholds,
collection, retention, indexing delays, permissions, profile coverage, literal
field matching and limits affect what can be found. Empty results establish
only that this bounded search returned no matching visible alert documents.

## Validation

`python scripts/validate_related_events.py` provides 16 isolated check groups
covering requests, query authority, provider identity, returned-scope enforcement,
account roles, IP/GUID/session filters, projection, duplicates, general alerts,
tool errors and budgets, planning, invocation isolation and a scripted native
tool call persisted through worker completion. It uses fresh databases under
ignored `data/validation/related-events-*`, with in-memory source/model substitutes.

The checks have been added but have not yet been executed. Live Indexer field
mapping and model tool-selection/report quality remain separate validation.

## Profile references

- [Microsoft audit configuration catalogue](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft security group auditing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
- [Microsoft process creation auditing](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
- [Microsoft Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Wazuh alert and archive coverage](https://documentation.wazuh.com/current/getting-started/use-cases/log-analysis.html)
