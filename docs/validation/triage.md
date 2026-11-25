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
