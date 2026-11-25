# Background investigations

- Ingestion stores an alert and its triage decision in one transaction.
- Eligible alerts schedule individual jobs or join a matching pending group.
- Suppressed alerts remain stored without an automatic job.
- A grouped job analyzes a consistent snapshot of all retained group members.
- Group membership stops growing as soon as the representative job is claimed.
- Workers claim jobs using expiring leases and unique claim tokens.
- A heartbeat renews the lease during analysis.
- Report storage, job-result linking, and job completion share one transaction.
- Expired workers cannot finalize jobs.
- Retryable failures use bounded attempts and increasing delays.
- Ctrl+C finishes the current investigation before stopping.
- Processing may repeat after a crash; inference is not exactly once.
- Completed reports remain provisional and require analyst review.
- Manual checks have validated Wazuh delivery and the worker lifecycle.
  Active Directory report validation is in progress.

## Targeted investigations

Use `python -m cybertriage worker --once --job-id JOB_ID` to process one
specific eligible job. Omitting `--job-id` preserves normal queue selection.

Targeted selection applies to both claiming and attempt-exhaustion updates,
leaving other jobs queued. Lease ownership, retry availability, attempt limits,
and atomic completion still apply. A job that is completed, failed, waiting for
its retry delay, or owned under a valid lease is not eligible for processing.
