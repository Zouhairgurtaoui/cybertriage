# CLI guide

Run native commands from the repository root with the project virtual environment
active. Installation and Docker startup are in the [README](../README.md).
Use `python -m cybertriage COMMAND --help` for the complete options of a command.

## Reference knowledge

```bash
python -m cybertriage catalog-update
python -m cybertriage ingest --source mitre
python -m cybertriage ingest --source microsoft
python -m cybertriage event-lookup --event-id 4728
```

Ingestion downloads configured source documents and creates embeddings through
the external Ollama service. The source policy is `config/sources.yaml`; the
catalogue and Chroma collections are stored under ignored `data/` directories.
Finish maintenance before starting analysis against the corpus.

## Analyze evidence

```bash
python -m cybertriage analyze --evidence examples/alerts/privilege-change.txt
python -m cybertriage analyze-stored --record-id ALERT_RECORD_ID --investigate
python -m cybertriage worker --once --job-id JOB_ID --investigate
```

Replace identifiers with actual retained IDs. `--job-id` targets an eligible
job; it does not reopen a completed job. Use a case investigation request when
new work is needed. Standalone file analysis prints a report; the saved-report
browser reads the retained analysis database, not arbitrary output JSON files.

`--offline-knowledge` disables live public-document lookups for supported analysis
commands. It does not disable Indexer tools selected through `--investigate`.

## Native services

```bash
python -m cybertriage serve
python -m cybertriage serve-analyst
python -m cybertriage worker --investigate
python -m cybertriage investigation-worker
python -m cybertriage response-expiry-worker
```

These are separate long-running processes. Configure credentials before starting
them; use the platform Docker launcher for a shared lifecycle. Native CLI
configuration reads ignored `.env.local`. Docker uses `.env.docker.local` and
explicit secret-file mounts instead.

## Search indexed authentication

```bash
python -m cybertriage search-authentication --account ACCOUNT --domain DOMAIN --start "2026-09-01T02:24:50Z" --end "2026-09-01T02:25:00Z" --limit 10
```

The search uses the configured read-only Indexer account and verified CA.
Coverage is limited to visible indexed Wazuh alerts. Empty results do not prove
the activity never occurred. See [investigation tools](architecture/investigation-tools.md)
and [related events](architecture/related-events.md) for scope and field mappings.

## Analyst credentials

```bash
python -m cybertriage analyst-password --analyst-id local-analyst --username local-analyst
```

Run from an interactive terminal with the project Python environment active.
The password and confirmation are hidden; no password argument is accepted.
The command updates only the existing principal's username/password hash in
`config/analysts.local.yaml`. Permissions and API-token hashes are retained.
After provisioning or rotation, recreate the analyst API container to refresh
its mounted configuration file. No password is stored in `.env`.


```bash
python -m cybertriage analyst-key
```

This deliberately prints a new token and its hash. Store the token privately;
put only its hash in the analyst configuration with explicit permissions, case
scope and a future timezone-qualified expiry. The platform launcher's configure
step creates one investigation/review principal only when no local analyst file
exists. It does not rotate existing credentials.

## Case graphs

The React console reads the authoritative case projection from the analyst API.
Optional Neo4j publication adds a graph database projection; it does not replace
SQLite evidence or make inferred relationships observed facts.

Start the Docker launcher with `--graph` on Linux or `-Graph` on Windows to
include Neo4j, schema initialization and the graph worker. Native graph commands
and data semantics are described in [case graphs](architecture/graph.md).

## Validation tools

`scripts/validate_*.py` contain the retained validation suites. They use their
documented fixtures and prerequisites; generated results belong under ignored
`data/validation/`. See [evaluation](evaluation.md) and
[implementation status](implementation-status.md) for recorded coverage and
pending acceptance work.
