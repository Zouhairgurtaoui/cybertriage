# Response workflow and firewall adapters

Response proposals, analyst decisions and execution results are retained in the
same SQLite database as cases. Model reports can suggest actions but cannot
approve, confirm compromise or invoke an executor through investigation tools.
Both the operator CLI and authenticated analyst API use `ResponseWorkflow`.

## State and authority

1. A proposal identifies a case, allowlisted action/target, exact parameters,
   supporting active alert IDs, rationale, origin and idempotency key. Source
   payload hashes, policy/target revision and the resulting case version are
   retained. A linked report is optional and must belong to the case.
2. Approval requires a configured executor, confirmed compromise in the stored
   case, unchanged evidence/case version, matching policy/target revision and
   enabled execution. Approval records the authenticated analyst or asserted
   local CLI actor, exact binding hash, resulting case version and expiry.
3. A separate execute operation rechecks authority and obtains one dispatch
   claim. Review never executes an action. Rejection/revocation is append-only;
   an already claimed action cannot be revoked as though no command was sent.
4. Results distinguish `succeeded`, `failed` and `unknown`. An exception after
   dispatch may mean the appliance applied the change. Unknown outcomes require
   reconciliation; they are never automatically retried as a new action.

Changing case data, adding a report/note, modifying target configuration or
changing response policy invalidates outstanding approval authority. Proposal
creation and review append case events and bind the resulting versions, so
their own audit writes do not immediately invalidate their authority. Approval
expires independently of case changes. New approval after expiry or a stale
proposal requires a new proposal and idempotency key.

An exact proposal retry with its original idempotency key/content returns the
stored record. Different content conflicts. There is one dispatch record per
proposal, including failures. Lost execution responses are resolved with a read,
not another dispatch. Additional remediation requires a new reviewed proposal.

## Transactions and failure boundary

Proposal/review/dispatch claim writes and their case audit events share SQLite
transactions. Concurrent dispatch claims serialize and only one can be created.
Proposal, review and execution-event tables reject ordinary UPDATE/DELETE.
Runtime execution/lease states are mutable projections with retained audit
events. Database administrators can still change files/triggers; this is not
an externally tamper-proof ledger.

The appliance API and SQLite do not share a transaction. Approval is consumed at
the successful claim transaction; subsequent case changes cannot retract a
request already sent to the firewall. No exactly-once remote-effect guarantee is
claimed. A crash before sending may leave `dispatching`; a crash after sending
may leave the same state. Stop/fence the original dispatcher, inspect the device,
then use explicit reconciliation with evidence and a reason. Reconciliation
invalidates the old completion token through the execution-state check.

Policy and target files are loaded for each CLI/API response operation. Do not
change bindings while dispatchers or expiry workers are in flight. Secret values
are not stored in snapshots; named environment-variable references and public
target settings contribute to the target revision. Credential rotation does not
change an action's target binding. Enabling/disabling execution changes the
response policy revision, invalidating old approvals.

## Vendor boundary

`ActionExecutor` defines execution of an approved action. `FirewallGateway`
defines a narrower device capability: validate the configured block container,
check membership, add an address and remove it. `ManagedIpBlockExecutor` and the
expiry service use that gateway without vendor-specific branches.

The composition root registers providers by driver name. OPNsense is implemented;
FortiGate and pfSense require their own concrete gateway/configuration validation
for their supported API versions. They are not silently mapped to OPNsense and
are not currently advertised as operationally supported.

The OPNsense adapter uses a named, preconfigured, exclusively managed external
alias. It verifies that the alias exists, is enabled and is external; it refuses
to acquire an address already present. It sends only single-address operations,
never arbitrary rule definitions, shell commands, table flushes or state kills.
TLS certificate verification is mandatory, redirects/environment proxies are
disabled, response JSON is validated and response size/time budgets are bounded.
Keys and secrets come from configured environment-variable names.

The adapter follows the official [firewall API](https://docs.opnsense.org/development/api/core/firewall.html)
and [alias behavior](https://docs.opnsense.org/manual/aliases.html). Alias membership
must be referenced by a correctly placed block rule. Insertion plus a successful
membership read is recorded as `alias_membership_observed`, with
`traffic_block_verified: false`. Existing firewall states are not removed;
traffic on a path that does not traverse the firewall is unaffected.

## Block duration and ownership

The selected OPNsense alias interface has no per-entry TTL parameter. Duration
therefore uses a retained application lease and an independent expiry worker.
This is explicitly enabled with `application_managed_expiry: true` in target
configuration, together with `exclusive_alias: true`. It is not a native device
expiry guarantee. Host suspension, worker outage or appliance unavailability can
extend the block beyond the requested duration.

Leases are saved before dispatch, with expiry measured from the claim. Only
successfully observed additions become eligible for automatic removal. Unknown
additions hold the target/address until an operator establishes the actual state.
Preflight failure or a preexisting address creates no removal ownership. The same
target/address cannot have another active or unresolved lease.

An expiry worker claims a due lease, removes only its address, verifies absence
and appends the result. It does not rearm actions or require execution to remain
enabled. Unknown/stale release claims are not automatically reclaimed, because
a late remover could otherwise delete a later block for the same address.
Stop/fence the old worker, verify absence, then reconcile release. That operation
cannot reconcile an unresolved addition: establish its execution outcome first.
The alias must have no other writers; concurrent manual edits cannot be fenced
by this API. Device-native TTL needs a different capable adapter or appliance
extension when strict expiry during application outages is required.

## Operational status

Response defaults remain disabled and no device is configured by the shipped
template. No firewall rule, credential or live case disposition is created by
installation. Syntax/import/CLI checks do not validate appliance compatibility,
rule placement, actual traffic impact or expiry during outages. Runtime acceptance
and regression validation remain pending.
