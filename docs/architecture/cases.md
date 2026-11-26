# Incident cases

A case is an explicitly assembled investigation containing retained Wazuh
alerts, analyst notes, stored reports, and relationship assertions. Attaching
two alerts does not establish a common attacker or an attack chain. Cases can
span alert types and hosts; they are independent of the pre-analysis grouping
policy that shares a pending job among similar alerts.

## Application boundary

`CaseManagement` validates operator commands and depends on `CaseRepository`.
`ObservedRelationshipPolicy` proves supported relationships from structured
alert fields. `SqliteCaseRepository` implements persistence and transaction
boundaries. The composition root assembles these components. The CLI adapter
handles argument parsing and serialization; neither the application service
nor the relationship policy depends on argparse, SQLite, LangChain, or Neo4j.

Case commands operate on the existing alert database. They do not invoke a
model, contact Wazuh, or require the lab VMs to be running. The schema is
created additively when case/report storage is opened. Existing alerts and
jobs are not reclassified or assigned to cases automatically.

## Lifecycle and findings

Cases have a title, description, priority, status, disposition, creation and
update timestamps, and a monotonically increasing version. Status is `open`,
`investigating`, `resolved`, or `closed`. Disposition is `unconfirmed`, `benign`,
or `confirmed_compromise`. Closing a case does not imply a disposition.

Metadata changes, detachment, and relationship reviews require the version
last read by the operator. A stale version fails without partial changes.
An explicit `confirmed_compromise` command requires a reason and supporting
alerts actively attached to the case. This records an operator finding;
it does not certify that finding or authorize a response action. Neither
model prose nor report completion changes status or disposition.

Resolved and closed cases must be reopened before attaching/detaching evidence
or adding/reviewing relationships. Notes and newly completed report links can
still append to their history. Additive attachments and notes serialize in a
write transaction. Repeating an active attachment is a no-op. Detachment marks
membership inactive; it retains the source alert, relationships, reports and
all previous history. Historical findings remain recorded after detachment.

## Relationships

Relationship endpoints are stored alert record IDs, not arbitrary names. Both
endpoints and any supporting alerts must be actively attached to the same case
when the relationship is created. Each assertion records kind, predicate,
rationale, actor, evidence provenance and timestamp.

| Kind/predicate | Requirement and interpretation |
| --- | --- |
| observed / `shares_host` | Same manager and agent ID. |
| observed / `shares_account_fields` | Equal Windows account/domain fields, including target/initiator roles, within one manager; or equal Linux destination-user fields on one host. This is field equality, not human identity. |
| observed / `shares_source_ip` | Equal valid addresses within one manager. Loopback/link-local addresses also require the same host; unspecified addresses are rejected. IPv4-mapped forms normalize to IPv4. Shared IPs do not identify an attacker. |
| observed / `shares_session` | Same host/manager and nonzero reported Windows Security logon ID. Event 4624 supplies its target logon ID; other supported Security events supply a subject logon ID. Event 4625 is excluded because its subject is not the failed target session. IDs can be reused after reboot. |
| observed / `precedes_by_reported_time` | Source timestamp precedes target timestamp. Clock accuracy and causation are not established. |
| hypothesis / operator predicate | A bounded identifier, rationale and supporting attached alerts. Optionally references a report already linked to this case. It remains an inference. |

Observed assertions are checked against integrity-verified original alert
payloads and retain the source/target SHA-256 hashes, compared fields and
interpretation limits. Report text cannot serve as observed proof.

Hypothesis reviews can be `accepted`, `rejected` or `superseded`. Accepting a
hypothesis leaves its kind as `hypothesis`. Observed assertions can be
`retracted` or `superseded`. To record a new observation, create a separate
assertion that passes the structured evidence check. Assertions and reviews
are immutable; the latest review is a view over their preserved history.

## Reports and investigation history

Report insertion records its input alert coverage and links it to cases with
matching active attachments. These writes and their case-history events run
inside the same transaction as report storage and, for background processing,
job completion. A linking/audit failure rolls the completion back.

Coverage always includes the anchor alert. Grouped coverage additionally uses
the actual application-generated `group_id` and alert identities saved in the
report evidence snapshot, checked against stored group membership. Current
group membership alone does not establish past report coverage. Tool search
hits do not automatically become attached source alerts.

Attaching evidence backfills matching older reports, including legacy records
with no coverage rows. A legacy report without a recognizable structured group
snapshot covers only its anchor. Backfill is bounded to 1,000 reports and
8 MiB of evidence per attachment command; exceeding the budget rolls the
attachment back and requires a bounded migration. It never guesses coverage
from model text.

Reports may cover additional alerts outside a case. The report view lists all
covered alert IDs and their current membership state; it does not attach those
other alerts. Reports, references, investigation tasks, query scopes and tool
executions remain available in the original saved report. Reports linked before
detachment remain in the investigation history.

## Timeline and audit

The timeline combines source alert timestamps, report completion timestamps,
and recorded workflow events. Every item includes a separate recorded timestamp.
Source chronology is not a claim of causation. Detached evidence remains visible
with its current attachment flag. The history endpoint lists workflow events in
append order and includes before/after metadata, notes, attachment reasons,
relationship assertions/reviews and report links.

SQLite triggers reject ordinary UPDATE/DELETE operations on case events,
relationship assertions/reviews, report coverage and case-report links. These
constraints protect application history; they are not a tamper-proof log against
a database administrator who can replace files or drop triggers. Existing alert
hashes support integrity checks but do not establish trusted external origin.

Reads are paginated at 1–100 items. Timeline cursors bind the case ID, version
and last ordering key. Any case change, including an automatically linked
report, invalidates a previous timeline cursor; restart that timeline to obtain
a consistent snapshot. Other history listings use monotonically increasing
sequence cursors. Case listings use case-ID order, not creation-time order.
Page output is capped at 512 KiB; report output is capped at 2 MiB. A case can
retain 1,000 historical alert memberships; an alert can belong to 20 active cases.

## Security and integration boundary

Case mutation is available through local operator services and the separate
[authenticated analyst API](analyst-api.md). The ingestion token grants no
case-review capability. CLI actors are asserted local metadata; API actors come
from authenticated principal configuration. Model tools cannot mutate cases.
Local database and operating-system permissions remain necessary.

Complete reports and tool-driven investigations require global evidence access;
case-scoped reads cannot reveal group inputs or tool results outside their case.
[Response proposals, approvals and OPNsense execution](response-workflow.md) use
stored case findings and independent authorization checks. SQLite is authoritative.
The optional [case graph projection](graph.md)
exports retained evidence to JSON/Neo4j, with explicit evidence-backed Cyber Kill
Chain assessments and append-only reviews. Retained-alert correlation candidates
use explicit reported-field/time coincidences without automatic attachment.
Confirmed causal attack reconstruction and the analyst web graph remain separate
work; a timeline or accepted hypothesis does not fill missing attack stages.

## Offline validation

Run `python scripts/validate_cases.py` from the project root. It creates isolated
databases under ignored `data/validation/cases-*` and uses synthetic reports.
Checks cover lifecycle and concurrency, evidence/provenance rules, report
backfill and exact group snapshots, job-completion rollback, pagination,
case boundaries and append-only history. No model, VM or Indexer is needed.

These checks have been added but have not yet been executed. They assess
storage and orchestration behavior, not real-world attack attribution or
model report quality.
