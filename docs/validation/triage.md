# Triage and grounding validation

Use an isolated SQLite file and controlled alert fixtures before enabling a
suppression rule in an operational configuration. Preserve the original database
and validate deployment-specific Wazuh field names.

## Configuration and operator commands

```powershell
python -m cybertriage triage-policy
python -m cybertriage triage-inspect --help
python -m cybertriage triage-feedback --help
python -m cybertriage triage-release --help
python -m cybertriage triage-evaluate --help
```

The default policy must report zero suppression rules and one grouping rule.
Invalid keys, duplicate IDs, invalid field paths, naive timestamps, and excessive
suppression validity periods must reject configuration.

## Ingestion checks

| Scenario | Required result |
|---|---|
| No suppression match | Stored alert, audited investigate decision, one job |
| Exact active suppression match | Stored alert and audited suppression; no automatic job |
| Expired rule or missing field | Individual analysis remains eligible |
| Severity/protected-event override | Individual investigation despite a suppression match |
| Same alert delivered twice | Same decision and scheduling association; no extra member or job |
| Same source identity with changed content | Conflict; no partial transaction |
| Matching burst before claim | One representative job and retained member alerts |
| Different manager/host/account/window | Separate groups/jobs |
| Group reaches five members | Next alert starts a new job; no dropped event |
| Matching arrival after claim or completion | New group/job; existing report membership unchanged |

Grouping includes an initial ten-second delay by default. A worker run before
the job's available_at is expected to find no eligible job. Restart the API and
worker to load updated application code; existing queued jobs remain scheduled.

## Worker evidence

Process the representative job and inspect the stored AnalysisRecord evidence.
Every group member's source alert identity must be present. Verify the declared
member count, fixed window, omitted-raw-context flag, and sourced code definitions.
The snapshot must not imply that membership proves one attack or actor.
Verify crash recovery and lease ownership still prevent stale completion.

## Feedback and evaluation

Record known fixture labels with triage-feedback, then inspect the history.
Confirm a later label appends history. Malicious/uncertain feedback on an
unscheduled alert must atomically create an individual job and override.
Benign feedback must not create a suppression rule or cancel a job.
Release must not change a label or overwrite an existing completed report.

Evaluate fixtures containing benign and malicious suppressed examples. Confirm
the malicious suppression remains counted after release. Check overall and
per-revision metrics, null zero-denominator rates, uncertain-label exclusion,
and explicit untriaged historical counts. Treat limited label coverage as a
limitation; do not infer population-wide accuracy.

## Grounded investigation report

Run the README authentication investigation against a known retained event.
Inspect the saved tool record, not only the report text. Its summary must show
the actual ten-second interval, searched event IDs 4624/4625, and returned count.
For substatus 0xc0000072, verify the supplied disabled-account definition and
its Microsoft source. The raw failure token %%2310 must remain unresolved.

Manually compare report claims with the structured result. Unsupported claims
about incorrect passwords, global absence of events, benign intent, or account
lockout are report-quality failures even when the search succeeds. Unknown
registry codes must remain unknown. Oversized tool results must produce an
explicit error rather than silently incomplete evidence.

## Recorded validation — 2026-11-25

### Grouping and duplicate delivery

An isolated database retained two distinct matching failed-logon alerts,
two immutable ingestion decisions, one candidate group, two memberships,
and one representative job. Re-delivery of the second alert reused its record,
decision, group, and job without adding rows.

Validation database: `data/validation/triage-grouping-3af2ad9ec77240b79c973e938bf912b2.sqlite3`.

The representative worker job completed on attempt 1. Analysis
`853be1104eda40fcbfeb13af77b79175` contained both distinct source identities
and a sourced substatus definition for each member. The report interpreted
0xc0000072 as a disabled account at the time of the attempts.
The five-minute grouping bucket and the one-second observed event span are
different quantities; report wording still requires scope and accuracy review.

### Suppression, overrides, and feedback

A separate seven-alert fixture database verified:

- Exact active exceptions retained two alerts without automatic jobs.
- Account mismatch, missing fields, expired exceptions, severity overrides,
  and protected-event overrides scheduled individual analysis.
- Uncertain feedback released an unscheduled alert for analysis.
- A later malicious label preserved feedback history and reused the same job.
- Benign feedback retained suppression without creating a job.
- The final state contained six jobs for seven retained alerts.

Validation database: `data/validation/triage-review-03b74913bfb84d2cb0d5e99b7ba1fce4.sqlite3`.
Evaluation report: `data/validation/triage-quality-03b74913bfb84d2cb0d5e99b7ba1fce4.json`.

### Evaluation calculations

The fixture deliberately assigned one benign and one malicious label to alerts
matching the same suppression exception. Five alerts remained unreviewed.

| Measurement | Observed value |
|---|---|
| Original investigate decisions | 5 |
| Original suppress decisions | 2 |
| Label coverage | 2/7 (28.57%) |
| Suppression label coverage | 2/2 (100%) |
| Reviewed suppression precision | 1/2 (50%) |
| Malicious suppression rate | 1/1 (100%) |

The malicious original suppression remained counted after feedback released its
alert. These intentionally adverse fixture values verify accounting and audit
behavior; they do not estimate operational suppression quality or detection
accuracy. The default operational configuration still has zero suppression rules.

### Remaining coverage

The recorded runs do not establish group behavior at the member limit, arrivals
after claim/completion, host isolation, rollback under storage failure, audit
trigger enforcement, or complete report accuracy. Zero-denominator evaluation
rates, uncertain final labels, and pre-policy populations require additional
cases. The isolated fixture ingestion exercised application/storage behavior;
HTTP ingestion with the revised triage response also requires regression coverage.
