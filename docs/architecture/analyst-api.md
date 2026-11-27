# Analyst API

The analyst API is a separate FastAPI application and listener from Wazuh
ingestion. It accepts password-issued sessions and existing per-analyst API tokens with explicit permissions,
case scope and expiry. The ingestion token grants no analyst capability.
Installation, credential generation and startup commands are in the README.
The React application is built and served separately. This listener serves JSON
and does not mount frontend assets; its root identifies the API service.

## Authentication and authorization

Configuration stores SHA-256 hashes of high-entropy generated API tokens, not
plaintext credentials or password hashes. Token comparisons use constant-time
digest comparison. The configuration is reloaded on each authenticated request,
allowing subsequent requests to observe revocation, expiry and permission changes.
Already accepted background investigations are retained authorized work; token
revocation does not automatically cancel them.

The server supplies the analyst ID to audit services. Request models reject
extra fields, including client-supplied actor or approval-authority overrides.
Password login issues opaque server-side sessions; this is not an OIDC implementation.
The separate React application keeps tokens in page memory and uses a same-origin
API proxy. A future identity-provider/session adapter can replace token entry
without changing case and response services. No cookies, cross-origin credentials
or wildcard CORS are enabled. See [frontend boundaries](analyst-web.md).

Permissions are independent:

| Permission | Capability |
| --- | --- |
| `cases:read` | Authorized case metadata, history, timeline, graph and response reads. |
| `cases:write` | Notes and evidence/relationship operations. Global evidence access is additionally required for attachments, relation creation and new cases. |
| `cases:review` | Explicit case findings and relationship/Kill Chain reviews. |
| `investigations:request` | Queue read-only re-investigations; requires global evidence scope. |
| `reports:read_all` | Read complete reports and their tool evidence; requires global evidence scope. |
| `responses:propose` | Create evidence-backed proposals. |
| `responses:approve` | Approve/reject/revoke proposals, without executing them. |
| `responses:execute` | Dispatch a current authorized proposal. |
| `responses:reconcile` | Record verified outcomes for unresolved dispatch/removal operations. |
| `triage:review` | Append labels/release and inspect suppression evaluation; requires global evidence scope. |

Case scope is an explicit list of case IDs or the sole wildcard `*`. The
wildcard is a broad configured grant, not a default permission. Case listing
filters to that scope without leaking pagination keys from unauthorized cases.
Every case path is checked before invoking a service. Proposal reads/actions
also verify that the proposal belongs to the path's case.

Read-only tools can retrieve related evidence outside a case's original alert
attachments. For that reason full reports, report listings, candidate discovery
and investigation requests currently require global evidence access. A
case-scoped credential can read its case metadata/graph but cannot use those
operations to retrieve other evidence. Finer host/account/evidence authorization
requires a dedicated entitlement model; case membership alone does not provide it.

## API surfaces

| Route family | Behavior |
| --- | --- |
| `/api/v1/auth/login`, `/api/v1/auth/logout` | Password login and explicit session revocation. |
| `/api/v1/me`, `/api/v1/schema` | Current permissions and authenticated OpenAPI contract. |
| `/api/v1/alerts`, `/api/v1/alerts/{record_id}` | Bounded retained-alert inbox and evidence detail; global evidence scope required. |
| `/api/v1/analyses`, `/api/v1/analyses/{analysis_id}` | Newest-first saved reports, optional alert coverage filter and retained report detail; global scope plus `reports:read_all` required. |
| `/api/v1/cases/{case_id}/conversation`, `/conversation/{turn_id}` | Persistent case turns, bounded history and reply provenance. Reads require global report access; sending also requires investigation-request and case-read permissions. |
| `/api/v1/cases` | Scoped listing and explicit case creation. |
| `/api/v1/cases/{case_id}` | Case metadata and versioned review updates. |
| `.../alerts`, `.../notes`, `.../relationships`, `.../stages` | Existing application services with server-derived audit actors. |
| `.../timeline`, `.../graph`, `.../sections/{section}` | Retained history and bounded source-derived graph JSON. |
| `.../candidates` | Retained-alert host/account/time coincidences for review; no automatic attachment or attack classification. |
| `.../reports/{analysis_id}` | Complete saved report and input-alert coverage. |
| `.../investigation-requests` | Durable requested investigations and status/report IDs. |
| `.../responses` | Proposal creation, listing, detail, reviews, explicit execute and reconciliation. |
| `.../response-capabilities` | Nonsecret configured actions and executor targets; grants no approval or execution authority. |
| `.../alerts/{alert_id}/feedback`, `/api/v1/triage/evaluation` | Existing append-only analyst labels and suppression-quality evaluation; active case membership is checked before feedback. |

Use the authenticated schema for exact field names and request contracts.
Mutation bodies are read after authentication, require JSON, reject duplicate
keys/nonstandard numeric constants and are limited to 16 KiB with a read timeout.
Pydantic models reject unknown fields and coercion. Case reads retain existing
pagination/result limits; graph output retains its graph budget.

Version conflicts return 409, invalid application requests 400, storage failures
503, missing/expired credentials 401 and unauthorized capabilities 403. HTTP
200/201/202 is transport/workflow completion, not factual certification of model
reports or proof of effective traffic containment.

The health endpoint exposes only process liveness. API docs/schema are not
published anonymously. Responses disable caching and framing and set nosniff and
referrer protections. The CLI binds to loopback by default; direct non-loopback
binding requires a TLS certificate/key. A TLS reverse proxy may target loopback.
Concurrency is bounded and default analyst access logging is disabled to limit
case-ID exposure. Server/filesystem permissions remain necessary for configuration,
database, logs and credentials.

## Requested investigations and correlation candidates

Explicit requests have an idempotency key, actor, anchor alert, task and case
version. They use a separate leased queue and results table; automatic jobs and
previous reports are preserved. Request metadata is immutable. The existing
heartbeat, retry, stale-claim rejection and atomic report/job completion are
shared through adapter-owned fixed table identifiers.

The worker rechecks that the case is open and the anchor actively attached.
The analyst objective augments an application-generated plan; it cannot expand
the plan's allowed accounts, manager/host scope, time window or tool budget.
Actual input-alert coverage and new reports use the existing case linking path.
Case/global limits bound retained and pending requests. The HTTP request only
queues work; it does not run the model in the web request.

Candidate correlation is restricted to retained alerts from the same manager,
within at most one hour of an active anchor, sharing a reported host or complete
account/domain fields. At most 2,000 candidates are examined and requested output
is bounded; an oversized scope fails rather than silently selecting from a
truncated scan. Results retain evidence hashes, field roles and time distance.
They do not prove a common person, lateral movement, causal ordering or compromise.

## Acceptance status

The API, request queue and response workflow have been implemented with static
syntax/import checks. Live HTTP authorization, queue regression, model behavior,
firewall execution and deployment acceptance remain to be validated. The separate
React interface has been implemented; its dependency installation, build and
browser/API acceptance remain pending.

## Saved agent reports

The global report list includes automatic analyses and requested investigations,
including reports not attached to cases. `alert_id` filters by report anchor or
recorded input coverage, so a grouped member can locate its shared report.
Legacy reports without coverage metadata can be found through their anchor.
Pagination uses a bounded descending local SQLite sequence, separate from
incident timestamps. Listing or opening reports performs no model or tool calls.

Alert details expose a limited job projection (ID, status, attempt count and
error code). Grouped members resolve to the representative automatic job;
claim tokens and lease ownership are not exposed. Neither report visibility nor
job completion changes case findings or response authorization.

## Password login and sessions

`POST /api/v1/auth/login` accepts a username/password and returns a new opaque
bearer token, its type and expiry. Passwords use fixed-cost scrypt
(N=131072, r=8, p=1) with a distinct 16-byte salt and a 32-byte derived hash,
following [OWASP's scrypt guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
Provisioning requires the local `analyst-password` command and an existing
principal; it cannot grant roles, create an administrator or change case scope.
No default password or public registration endpoint exists.

Sessions expire after at most 15 minutes and never outlive their analyst
configuration expiry. Only the token's SHA-256 digest is stored in the ignored
session database. Authentication reloads the account policy; password, username,
permission, scope or credential-expiry changes invalidate existing sessions.
`POST /api/v1/auth/logout` revokes the supplied session. Up to five active
sessions are retained per username; older sessions are revoked on new login.

Persistent login limits cover both the normalized username and direct client
address; forwarded headers do not grant a new throttle identity. Unknown users
pay the same password hashing cost, and concurrent hash work is bounded.
Responses use generic credential errors. API tokens remain compatible with the
existing configuration and expiry rules.

The browser retains a session bearer only in memory. A copied bearer can still
be replayed until revocation or expiry; username/password login limits exposure
but does not bind requests to a device. HTTPS protects credentials and bearer
transport outside loopback development. Server-side expiry and revocation follow
[OWASP session-management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
