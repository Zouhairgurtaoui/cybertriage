# Case graph and Cyber Kill Chain assessments

SQLite is authoritative for cases, attachments, source alerts, reports and
analyst decisions. A pure application service builds a deterministic,
case-owned graph from one read transaction. JSON export works without Neo4j;
the optional Neo4j adapter publishes the same graph. No model, VM or Indexer
is needed to export already retained evidence.

## Graph meaning

Each graph belongs to a namespace and a case. Node keys hash that scope,
entity kind and reported identity. Even identical alert/host/account values in
different cases receive different keys. This prevents implicit cross-case
merging; authorized cross-case correlation is a separate future capability.

| Graph element | Interpretation |
| --- | --- |
| `CTCase`, `CT_HAS_ALERT` | Stored case metadata and active/historical memberships. Membership does not establish a common attacker. |
| `CTAlert`, `CT_REPORTED_ON` | Immutable normalized alert hash and reported manager/agent identity. |
| `CTAccount`, `CTAddress`, process/session identifiers | Reported fields with their original field paths and roles on edges. Shared values do not prove a shared actor or causal connection. |
| `CTAssertion` | Retained observed relationship or analyst hypothesis, rationale, proof and review state. |
| `CT_OBSERVED_RELATIONSHIP` | An existing structured evidence-checked assertion; source and target hashes must still match. |
| `CT_HYPOTHESIZED_RELATIONSHIP` | An active working hypothesis. Accepting it preserves its hypothesis kind. |
| `CTTimeBucket`, `CT_NEXT_REPORTED_TIME` | Ordering of Wazuh alert timestamps. Equal timestamps share a bucket; ordering is not attacker causality. |
| `CTCaseEvent`, `CTReview`, `CTAnalysis` | Workflow history, append-only reviews and saved report metadata pointers. Full reports remain in SQLite. |
| `CTKillChainStage`, `CT_FRAMEWORK_NEXT` | Seven reference stages and framework order, independent of what the evidence establishes. |
| `CTStageAssessment`, `CT_ASSESSES_STAGE` | Explicit evidence-backed operator classification, with kind and active/review status. |

Accounts retain exact reported names/domains. Missing-domain accounts and raw
combined identities are host-scoped; domain labels remain reported values,
not verified directory principals or people. Loopback, unspecified and
link-local addresses are host-scoped. Other IPs are manager-scoped and do not
establish device ownership. Process GUIDs are host-scoped; PIDs are scoped to
one alert to avoid reuse. Security logon IDs preserve subject/target roles and
are host-scoped with a reboot-reuse caveat. Failed-logon event 4625 does not
create a successful-session identity.

Graph alerts omit raw full logs and decoded payloads. Process command lines,
passwords, credentials and full model reports are not automatically extracted.
Case notes, titles, rationale, account names and addresses can still be sensitive;
exports and the graph database need the same access controls as case metadata.
Report coverage edges include only alerts historically attached to this case;
coverage outside the case is represented by a count, without adding those IDs.

Detached alerts, rejected/retracted/superseded assertions and all reviews remain
in the graph history. Convenience relationship edges exist only while both
endpoints and all support remain active and the assertion has not been withdrawn.
The JSON `timeline` orders alert buckets; case workflow and report timestamps
remain on their own history/report nodes and in the complete SQLite case timeline.

## Explicit Kill Chain classification

The [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
defines reconnaissance, weaponization, delivery, exploitation, installation,
command and control, and actions on objectives. All seven stages appear in the
projection, initially `unassessed`. Framework edges describe reference order,
not a completed or continuous attack sequence.

`case-stage-add` accepts `hypothesis` or `analyst_assessed`, supporting active
attached alert IDs, actor, rationale and the current case version. It records
an assessment and a case-history event in the same transaction. Closed or
resolved cases must be reopened before adding or reviewing assessments.

Reviews append decisions. Hypotheses allow acceptance, rejection or supersession;
analyst assessments allow acceptance, retraction or supersession. Acceptance does
not promote a hypothesis, confirm attack success, change case disposition or
approve a response. An assessment without currently active support remains in
history but does not count toward the active stage summary. Conflicting
assessments are retained for review, rather than silently resolved.

Event IDs, ATT&CK mappings, temporal proximity, shared addresses and model prose
never automatically populate stages. Stage selection requires interpreting the
actual evidence. Missing phases remain unassessed; direct hypothesis edges can
describe a possible connection while evidence is collected.

## Snapshot and publication contract

The reader uses SQLite `mode=ro`, `query_only` and a single read transaction.
Composition first applies the existing additive case schema initialization.
It checks retained normalized-alert hashes and bounds historic memberships at
1,000, relationship/stage assertions at 2,000 each, their reviews at 5,000 each,
workflow events at 5,000, reports at 1,000 and each report's coverage at 1,000.
Snapshot data has an 8 MiB budget. Exceeding limits fails explicitly; it never
returns a silently truncated incident. A bounded migration or smaller case is
needed for oversized histories.

The graph is capped at 30,000 nodes, 150,000 edges and 16 MiB compact JSON.
Identity fields over 512 UTF-8 bytes fail projection. Hashes include stable
source content and projection policy, excluding read/publication timestamps.

`graph-schema` explicitly creates the unique `CTGraphNode.key` constraint.
`graph-sync` requires that constraint, locks the case root within a managed
write transaction, and checks source version and content hashes:

- Same version and hashes return `unchanged`; logical nodes/edges are not duplicated.
- An older version is rejected. Different content for an existing version is a conflict.
- Newer versions replace only this adapter's owned case projection atomically.
- Foreign-owned nodes cause a conflict. Stale projection nodes are deleted without
  `DETACH DELETE`, so unexpected external relationships cause rollback rather
  than being removed.

The case-root lock serializes same-case publications. Values are parameterized;
labels and relationship types come only from static registries. Transaction
retry callbacks do not mutate SQLite or call external tools. Driver-managed
writes have a 30-second transaction timeout, bounded retries/pool and connection
timeouts. Driver errors are wrapped without exposing credentials or query data.
See the [Neo4j Python managed transaction contract](https://neo4j.com/docs/python-manual/current/transactions/).

Neo4j is a dedicated projection: manage case changes through CyberTriage, rather
than editing its nodes manually. The runtime account needs graph read/write
and constraint-inspection privileges; schema setup can use a separate schema
administrator. Namespace is an application partition, not a substitute for
database authorization. Use a separate database/account where appropriate.

SQLite and Neo4j do not share a transaction. After publication, the service
checks the current SQLite case version and returns `needs_resync` if it advanced.
If that final check fails, the graph may already be published; re-running sync is
safe. A false `needs_resync` value means the versions matched at the check instant,
not that future changes are prevented. `graph-sync` publishes explicitly. The
optional `graph-worker` polls changed case versions with durable per-namespace
delivery cursors. Failures retain backoff; a cursor-write failure can cause an
idempotent repeat. This is incremental snapshot delivery, not a transactional
external outbox or freshness promise. See [backend operation](../operations.md).
Rebuild by syncing current cases into a new namespace/database. Projection-policy
upgrades that change same-version content require a new namespace or a genuine
subsequent case revision; conflicting content is never force-overwritten.

## Configuration and access boundary

Installation and commands are in the [README](../../README.md#case-graphs).
The official driver is optional and imported only by online graph commands.
Remote connections require certificate-verified `neo4j+s` or `bolt+s`.
Plain `bolt` is accepted only for direct loopback connections; self-signed
verification bypass, embedded credentials and plaintext routing are rejected.
An SSH tunnel can target a loopback Neo4j listener without public exposure.

Credentials come from environment variables or an interactive hidden password
prompt. `.env.local` is loaded by the existing CLI; secrets must stay ignored.
The graph adapter registers no HTTP endpoint, model mutation tool, shell tool or
response executor. Operator actor strings remain local asserted audit metadata.
An analyst web graph needs authenticated sessions and case/evidence authorization.

## Validation

`python scripts/validate_case_graph.py` creates isolated SQLite fixtures and uses
a scripted driver substitute. It covers deterministic/isolated graph identities,
chronology, relationship/stage lifecycle, evidence hashes, budgets, audit storage,
version conflicts, rollback, ownership, resync reporting and URI restrictions.
It has been authored but not executed. The substitute does not parse Cypher;
real Neo4j constraint compatibility, concurrent publication and graph browsing
still require server validation. No claim of attack reconstruction accuracy or
production readiness follows from syntax/import checks.
