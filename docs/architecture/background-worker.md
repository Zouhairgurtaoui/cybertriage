# Background investigations

- Ingestion stores an alert and schedules its job in one transaction.
- Workers claim jobs using expiring leases and unique claim tokens.
- A heartbeat renews the lease during analysis.
- Report storage, job-result linking, and job completion share one transaction.
- Expired workers cannot finalize jobs.
- Retryable failures use bounded attempts and increasing delays.
- Ctrl+C finishes the current investigation before stopping.
- Processing may repeat after a crash; inference is not exactly once.
- Completed reports remain provisional and require analyst review.
- End-to-end Wazuh validation is the next milestone.