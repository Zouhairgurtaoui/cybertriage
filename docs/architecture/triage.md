# Alert triage, grounding, and review

## Processing flow

An ingestion transaction stores the normalized alert, its policy decision,
optional candidate-group membership, and any required analysis job. The
transaction commits before the API acknowledges delivery. Original alerts
remain available regardless of the scheduling decision.

`AlertTriagePolicy` is a pure application policy. `YamlTriageConfiguration`
implements its configuration port; `SqliteAlertRepository` evaluates the
injected decision port inside its ingestion transaction. Review and evaluation
services depend on a review repository port. LangChain and SQLite remain in
adapters.

## Policy configuration

`config/triage.yaml` controls scheduling. Validate it with:

```powershell
python -m cybertriage triage-policy
```

The ingestion API accepts `--triage-config PATH`. Configuration is loaded when
the API starts; restart it after a change. Configuration errors fail startup.
Each decision records a SHA-256 policy revision; its canonical settings snapshot
is retained in `triage_policies`.

The decision order is:

1. A disabled policy schedules ordinary analysis.
2. Severity at or above `force_investigate_level` always schedules individually.
3. Protected Windows Security event identities always schedule individually.
4. A matching, active suppression rule retains the alert without an automatic job.
5. An eligible grouping rule may share a pending job with matching alerts.
6. Every other alert schedules individual analysis.

The default configuration enables candidate grouping for repeated Windows 4625
alerts and contains **no suppression rules**. Severity alone never establishes
that activity is benign.

### Suppression rules

Each rule requires an exact manager, agent, Wazuh rule ID, at least two exact
decoded-data values, a maximum severity below the override threshold, a reason,
and an explicit timezone-aware start and expiry. A rule lasts at most 30 days.
Both event time and ingestion time must fall inside its validity interval.
Missing fields do not match. Wildcards and executable expressions are unsupported.

Decoded-data paths are relative to Wazuh's `data` object. For example,
`win.eventdata.targetUserName` selects `data.win.eventdata.targetUserName`.
Rules require verified deployment-specific field names and values.

An illustrative maintenance rule has this structure; replace the placeholders
and dates with an approved, documented maintenance scope before activation:

```yaml
suppression_rules:
  - id: approved-maintenance
    source_instance: REPLACE_WITH_MANAGER
    agent_id: REPLACE_WITH_AGENT_ID
    wazuh_rule_id: REPLACE_WITH_RULE_ID
    fields:
      win.eventdata.targetUserName: REPLACE_WITH_APPROVED_ACCOUNT
      win.eventdata.logonType: "5"
    starts_at: "2026-11-25T22:00:00Z"
    expires_at: "2026-11-25T23:00:00Z"
    max_level: 5
    reason: "Approved maintenance; reference the verified change record here."
```

Suppression is an operator-defined scheduling exception, not a model finding of
benign intent. A disabled account, loopback address, or missing lockout event does
not independently qualify an alert for suppression.

## Candidate grouping

Grouping fingerprints include the policy revision, grouping rule, manager,
agent, Wazuh rule, complete event identity when available, selected decoded
fields, and a fixed UTC event-time window. Addresses such as 127.0.0.1 therefore
remain scoped to their reporting host.

Default groups use five-minute windows, a ten-second initial scheduling delay,
and at most five members. The delay allows a short burst to share one job and is
not extended by subsequent members. Alerts are never dropped when a group fills.

Membership can be added only while the representative job is pending. Claiming
and ingestion both use SQLite write transactions. Once a worker claims the job,
later alerts start a new group and job. Failed or completed jobs cannot absorb
new alerts. Expired claims retain their original bounded membership.

The worker receives a consistent group snapshot containing every member's source
identity, timestamp, rule metadata, selected fields, and applicable code
definitions. It does not analyze only the first alert. The evidence explicitly
identifies omitted raw context; full originals remain stored. An oversized
snapshot fails rather than silently dropping members. Its member IDs are retained
in the saved report evidence.

This is coalescing of similar alerts for resource control. It does not establish
a common attacker, causation, an incident timeline, or a Cyber Kill Chain stage.
Cross-technique incident correlation and Neo4j projection are separate features.

## Audit and duplicate delivery

`triage_decisions` records the action, reason, matched rule, policy revision,
group, timestamp, and any analyst override actor. `alert_group_members` preserves
membership. SQL triggers prevent updates and deletes of decisions, policy
snapshots, feedback, and membership through normal application operations.

Identical duplicate deliveries reuse the existing decision and job association;
they do not re-evaluate a new policy or enqueue suppressed/grouped alerts.
Conflicting source content remains an ingestion conflict. Existing pre-policy
jobs are preserved; duplicate delivery records a legacy decision when necessary.
Existing queue contents are not retroactively suppressed or grouped.

Schema additions are created idempotently at storage initialization. Back up
the SQLite database before deployment. The existing alert and job tables and
lease/heartbeat/completion rules remain in use.

## Factual grounding

`config/windows-authentication-codes.json` is a bounded, versioned registry of
sourced Microsoft definitions. The initial registry covers account restriction,
disabled-account status, and selected logon types. Unknown codes and `%%` resource
tokens remain unresolved; the model is instructed not to invent their meaning.
Each included definition retains a citation ID and source URL, and the result
records the registry hash. The registry does not perform live web requests.

Authentication tool output includes a deterministic search summary: the executed
start/end times, duration, account/domain filters, searched event IDs, returned
success/failure counts, truncation, and collection coverage. Counts describe the
returned set. The maximum allowed search duration is not the executed duration.
An authentication search does not establish whether a lockout event exists.

Stored-alert and grouped-worker evidence also includes applicable sourced code
definitions. Report prose remains provisional: supplying definitions and precise
scope does not guarantee that the model will use them correctly.

Sources:

- [Microsoft NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [Windows Security event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)

## Analyst feedback and release

```powershell
python -m cybertriage triage-inspect --record-id ALERT_RECORD_ID
python -m cybertriage triage-feedback --record-id ALERT_RECORD_ID --analyst ANALYST_ID --label uncertain --reason "Authorization evidence has not yet been retrieved."
python -m cybertriage triage-release --record-id ALERT_RECORD_ID --analyst ANALYST_ID --reason "Additional investigation requested."
```

Labels are `benign`, `malicious`, or `uncertain`. Every label is appended; a new
label supersedes the earlier label for evaluation without deleting history.
Benign labels do not create suppression rules or cancel jobs. Malicious and
uncertain labels atomically record an override and create an individual job if
none exists. Explicit release performs the same scheduling operation without
changing the latest label. Failed/completed jobs are not reset or overwritten;
use explicit stored-alert analysis for an additional report in those cases.

These are local operator commands protected by access to the application and
database. The analyst argument is an asserted audit identity, not authenticated
proof of identity. A future web API must obtain the actor from its authenticated
session and enforce review authorization. The ingestion token grants no review
API capability. Model output never calls these operations.

## Suppression evaluation

```powershell
python -m cybertriage triage-evaluate --output data/evaluations/triage-quality.json
```

Evaluation compares the original scheduling decision with the latest analyst
label. It reports overall and per-policy-revision counts, label coverage,
reviewed suppression precision, benign suppression/retention rates, and malicious
suppression/retention rates. Rates with zero denominators are null. Unreviewed and
uncertain labels do not become benign examples.

Reviewed suppression precision is the number of benign suppressed alerts divided
by all benign-or-malicious reviewed suppressed alerts. Malicious suppression
rate is malicious suppressed alerts divided by all reviewed malicious alerts
with a recorded policy decision. Retention rates are the corresponding fractions
that were not suppressed; grouped alerts are retained for analysis.

The original decision remains the evaluation basis after release, so an unsafe
suppression is not erased by a later override. Historical alerts without a
decision are reported as untriaged and excluded from policy label-based rates.
Evaluation is bounded to 100,000 alerts and fails rather than silently sampling.

Metrics describe reviewed scheduling decisions, not comprehensive attack
detection accuracy. Review selection can be biased. Initial jobs avoided are
counts of grouped/suppressed alerts, not measured token, latency, or cost savings.
Detection recall requires a representative labeled dataset and separate analysis.
