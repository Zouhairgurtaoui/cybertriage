# Backend operation

The backend is designed for a single application host with a local SQLite
database. Installation and initial configuration belong in the README.
Network storage for SQLite and unrestricted multi-host writers are not supported
deployment assumptions. An external database/storage adapter is needed for a
distributed deployment.

## Processes

The root Docker Compose project supervises these process roles as separate
containers. It supplies explicit loopback port publication, private API TLS,
startup dependencies, bounded Docker logs and restart-on-exit policies. An
optional profile manages Neo4j and graph publication. Wazuh/AD remain external.
Container health is process/dependency status, not investigation correctness;
see [container lifecycle and data](architecture/containers.md).

Run each enabled process under an appropriate service supervisor with the same
working directory and explicitly provisioned environment. The CLI reads ignored
`.env.local`; a supervisor can provide those variables directly. Processes do
not install models, grant firewall privileges or enable execution themselves.

| Process | Purpose |
| --- | --- |
| `serve` | Existing authenticated Wazuh ingestion listener, loopback by default. |
| `worker --investigate` | Automatic queued analyses and bounded read-only investigation. |
| `serve-analyst` | Separately authenticated case, graph, investigation and response API. |
| `analyst-web` | Separate React frontend, served by Vite for local development or Nginx in deployment; proxies API requests. |
| `investigation-worker` | Explicit analyst-requested investigations. |
| `response-expiry-worker` | Due IP-block removals; keep running while leases exist. |
| `graph-worker` | Optional changed-case publication to Neo4j. |

The graph worker polls case versions using SQLite delivery cursors per namespace.
Only successful publications advance a cursor. A crash after Neo4j commit but
before cursor commit causes an idempotent re-publication. Source changes during
publication remain eligible because only the delivered snapshot version is saved.
Failures retain a code and a 30-second retry delay. This is incremental snapshot
delivery, not a transactional external outbox or a promise that every intermediate
graph frame is published. Case workflow history remains retained in each snapshot.

Use a native service manager on the deployment host. Configure restart-on-failure,
log rotation and process resource limits there. Avoid running the model, reader,
API and firewall operations as a blanket administrator/root identity. Grant the
firewall API identity the minimum available alias read/update privileges. Device
ACLs may cover more than one alias; the adapter's fixed-alias restriction is an
application boundary, not a claim of appliance-level per-alias authorization.

## Connectivity and credentials

Frontend and analyst API are independently deployed processes. The frontend
does not read SQLite, Indexer credentials or firewall keys. Its same-origin
proxy forwards the analyst bearer credential to the API, which enforces case
scope and operation permissions. Restrict the upstream address at deployment;
use verified TLS for API hops across untrusted networks. A private CA must be
mounted read-only and the expected API TLS name must match its certificate.
The frontend health endpoint checks Nginx liveness, not API/worker readiness.
Local startup, package locking and deployment configuration are in the README.

Expose the analyst API through TLS and restrict ingress to intended analyst
clients. The ingestion and analyst credentials are independent. Do not put tokens
in query strings, logs, Git, exported reports or browser URLs. Local deployment
YAML and `.env.local` are ignored. Keep database/configuration/log directories
accessible only to the service accounts and authorized operators.

Indexer and firewall certificates must match the configured hostname/IP and
chain to the configured CA or system trust. There is no skip-verification switch.
Keep read-only Indexer credentials separate from firewall mutation credentials.
OPNsense external aliases need a matching blocking rule on the actual traffic
path. Same-segment workstation traffic that bypasses the appliance cannot be
contained through its rules.

## Shutdown and changes

Disable new response execution and stop accepting execute requests before
changing firewall bindings or response policy. Let in-flight dispatchers finish;
read unresolved statuses before restarting them. Keep the expiry worker running
for existing blocks. A changed target revision requires draining or reconciling
leases that used the previous bindings before changing device destinations.

Do not automatically replay `dispatching` or `unknown` actions after a crash.
Stop/fence the original process and inspect the appliance. Record a reconciled
execution outcome or verified block removal with evidence and a reason. A
successful local audit write does not prove the appliance's state. Pending
read-only investigation jobs can be recovered using their existing leases and
attempt limits; response mutations deliberately use a different failure contract.

Application-managed block expiry depends on a continuously available worker and
appliance. Laptop sleep or outages can extend duration. Use an appropriate always-on
host or a device-native TTL-capable adapter if expiry during application outages
is a requirement. Monitor unresolved leases and worker liveness explicitly.

## Backups and monitoring

Use SQLite's online backup API or stop writers before copying the database.
When operating in WAL mode, copying only the main file while writers run is not
a consistent backup. Protect backups as sensitive evidence and validate a restore
into an isolated directory. Back up configuration separately from environment
secrets. Neo4j is rebuildable from source cases into a fresh namespace/database;
it is not a substitute for backing up authoritative evidence and audit records.

Monitor queue age/depth, failed or exhausted jobs, unresolved response executions,
overdue block leases, unknown releases, graph delivery errors, authentication
failures and report-quality evaluation. The public health endpoint reports process
liveness only. Successful HTTP responses, worker completion and alias membership
do not certify detection quality, compromise attribution or actual containment.

## Release acceptance

Frontend acceptance additionally covers the locked dependency build, responsive
layout, keyboard/dialog/graph accessibility, scoped-credential visibility,
inactivity locking, stale-version conflicts, interrupted mutations and upstream
TLS failures. The production CSP must remain compatible with the built assets
without allowing inline scripts or arbitrary model-generated HTML.

Acceptance includes isolated storage/HTTP/concurrency regression, scoped tool and
live source behavior, a real Wazuh/AD event through retained reports/cases,
Neo4j publication, and an explicitly reviewed OPNsense lab block/removal with
observed traffic effects. Validate expiry across worker restarts and failure
reconciliation without enabling broad automatic responses. These runtime checks
are pending; static code verification does not establish production readiness.
