# CyberTriage

An AI assistant that helps SOC analysts
investigate Wazuh security alerts.

## Overview

CyberTriage will receive alerts from Wazuh, gather relevant context,
consult cybersecurity investigation procedures, and produce a report
for a human analyst to review.

The project combines Python, a locally hosted open-weight language
model, Retrieval-Augmented Generation (RAG), and agent tools using
LangChain and LangGraph.

## Problem

A security alert is the starting point of an investigation.

An analyst still needs to examine related events, consider possible
explanations, consult procedures, and decide what to investigate next.

CyberTriage aims to support this work by organizing evidence and
suggesting next steps while making uncertainty explicit.

## Project Objectives

The planned capabilities are to:

- Receive Wazuh alerts through a webhook.
- Retrieve relevant investigation procedures using RAG.
- Let an AI agent request additional context through controlled tools.
- Generate reports that distinguish facts, hypotheses, and missing evidence.
- Include references to the evidence and procedures used.
- Evaluate investigation quality using attack simulations and benign activity
  in a controlled lab.

The initial scope will focus on authentication alerts.
Response actions will remain under human control.

## Planned Architecture

Wazuh → Webhook receiver → Investigation agent → Report → Analyst review

The agent will access a local language model, a document collection,
and investigation tools.

## Current Status

The CLI supports MITRE/Microsoft knowledge retrieval, local Windows Security
event definitions, and analysis using `qwen3:4b-instruct` through Ollama.
Persistent incident cases organize stored alerts, timeline entries, investigation
notes, report history, and observed versus hypothetical relationships. Case
commands use SQLite and do not require a running model or lab VM.
The model returns a readable five-section report. Generation checks reject empty,
non-text, or unfinished responses; there is no required model JSON schema,
account-name masking, or automatic repair loop. Reports are provisional and
require analyst review. The instruct model is the development baseline, with
thinking disabled in the client configuration.

Knowledge ingestion and retrieval read `config/sources.yaml`. Response eligibility
reads `config/response_actions.yaml` through a separate application policy.
Default analysis combines semantic and BM25 retrieval with exact identifiers,
explicit platform compatibility and document diversity. Reports retain a
retrieval trace explaining the selected background references.
Authenticated Wazuh ingestion, SQLite-backed background analysis, and a read-only
authentication search are implemented. The analysis CLI supports opt-in model
tool calling. Persisted proposals/approvals and an OPNsense firewall adapter are
implemented behind explicit policy and analyst authorization checks.
Background workers support opt-in scoped authentication investigation. A separate
React analyst application provides case, evidence, investigation, graph and
response review screens through the authenticated analyst API. See
[implementation status](docs/implementation-status.md).

Ingestion includes auditable triage and candidate grouping before job scheduling.
Operator commands support analyst feedback and suppression-quality evaluation.
Authentication results include computed search summaries and sourced code
definitions. These features require deployment validation; model reports remain
provisional.

## Run the application with Docker Compose

The root `compose.yaml` starts the React/Nginx frontend, analyst API, Wazuh
ingestion API, automatic analysis worker, requested-investigation worker,
response-expiry worker and Ollama. The optional `graph` profile additionally
starts Neo4j, its schema initializer and the graph publication worker.
Wazuh, the Indexer and Active Directory remain external lab systems.

Use Docker Desktop with Linux containers and Docker Compose 2.24 or newer.
Run the following from the repository root in Windows PowerShell. Initial
configuration retains existing local files and asks for credentials without
echoing them:

```powershell
.\scripts\cybertriage.ps1 configure
```

This creates ignored `.env.docker.local` and secret files under
`config/secrets`. Enter the same ingestion token used by the Wazuh integration
and the dedicated read-only Indexer password. A random local Neo4j password is
generated once. The script does not replace existing credentials or configure
the Wazuh VM. Keep the provisioned `config/analysts.local.yaml` from the analyst
credential setup below; its token hashes and expiries are still required.

Edit `.env.docker.local` to set the reachable Indexer HTTPS URL, read-only
username and existing Ollama models directory. Copy the **public** Indexer CA
to the path configured by `CYBERTRIAGE_INDEXER_CA_PATH`, for example:

```powershell
Copy-Item "C:\path\to\root-ca.pem" config/certs/indexer-ca.pem
```

Container paths differ from Windows paths. The workers receive the CA as
`/run/indexer-ca.pem` and the model server is `http://ollama:11434`.
`localhost` inside a container refers to that container. If the Indexer is
reached through a Windows SSH tunnel, it must be reachable from Docker and its
TLS identity must still match the configured URL. Merely substituting
`host.docker.internal` for a certificate valid only for `127.0.0.1` will fail
verification. For an existing loopback-certificate SSH forward on host port
19200, configure:

```dotenv
CYBERTRIAGE_INDEXER_URL=https://127.0.0.1:19200
CYBERTRIAGE_INDEXER_FORWARD_HOST=host.docker.internal
CYBERTRIAGE_INDEXER_FORWARD_PORT=19200
```

Each worker opens a container-local TCP forward to the Windows SSH listener.
It forwards encrypted bytes without terminating TLS; the original CA and
certificate hostname checks remain enabled. Docker Desktop supplies the host
DNS name. Keep the existing host SSH forward running. For a directly reachable
certificate-matching Indexer endpoint, leave both forward variables empty.
Worker startup checks TLS, authentication and search permission using a
match-none query before claiming work; it retrieves no incident documents.

The frontend build uses the existing `node:26-slim` image selection and the
committed `apps/analyst-web/package-lock.json`. If the lockfile is absent, generate
it with the Node container instructions before building. Container images and
Python/Node dependencies may be downloaded during the initial build; **model
weights are not downloaded**. Ollama mounts the existing model directory
read-only and workers check that `qwen3:4b-instruct` and `nomic-embed-text` exist.

Build the images:

```powershell
.\scripts\cybertriage.ps1 build
```

For an existing native installation, stop its APIs/workers before migration.
Import its alert database, event catalogue and Chroma index **before the first
container startup**:

```powershell
.\scripts\cybertriage.ps1 import-data
```

The import copies `data/alerts`, `data/catalogs` and `data/chroma` into a named
Docker volume. Host files are read-only, existing container data is not
overwritten, and SQLite files use backup snapshots. Unresolved response
executions and outstanding/unresolved IP-block leases must be reconciled before
migration. Keep the existing corpus/source configuration when importing it.

For a fresh installation without an existing corpus, initialize the volume and
populate knowledge before starting the backend writers. The configured models
must already exist in the mounted model directory:

```powershell
docker compose --env-file .env.docker.local run --rm --no-deps bootstrap
docker compose --env-file .env.docker.local up -d ollama
docker compose --env-file .env.docker.local run --rm --no-deps worker catalog-update
docker compose --env-file .env.docker.local run --rm --no-deps worker ingest --source mitre
docker compose --env-file .env.docker.local run --rm --no-deps worker ingest --source microsoft
```

Catalogue/source ingestion needs public internet access; embedding uses the
existing local model. For later knowledge updates, stop the backend containers
first and repeat the maintenance commands with only Ollama running.

Start all core services with one command:

```powershell
.\scripts\cybertriage.ps1 start
```

Open **http://127.0.0.1:5173** and enter a provisioned analyst token. The web
container explicitly publishes `127.0.0.1:5173 → 8080`; Docker host networking
and manually started Node shells are not required. The ingestion endpoint remains
`http://127.0.0.1:8000/api/v1/alerts/wazuh`, preserving a host tunnel targeting
port 8000. The analyst API and Ollama ports are not published to the host.

To include Neo4j publication, select the graph profile:

```powershell
.\scripts\cybertriage.ps1 start -Graph
```

The new graph destination defaults to the `cybertriage-docker` namespace,
separating its delivery cursors from a previously used Neo4j destination.
Its password file initializes the local Neo4j account only on a fresh database;
changing that file does not rotate an existing database's password.

Routine operations:

```powershell
.\scripts\cybertriage.ps1 status
.\scripts\cybertriage.ps1 logs
.\scripts\cybertriage.ps1 stop
```

Stop retains named data/model-home/TLS/Neo4j volumes. Application-managed block
expiry stops with its worker, so drain/reconcile live blocks before taking that
service offline. Do not use `docker compose down -v` on retained evidence.

Equivalent direct Compose commands are available when a PowerShell wrapper is
not used:

```powershell
docker compose --env-file .env.docker.local up --build -d --wait --wait-timeout 300
docker compose --env-file .env.docker.local ps --all
docker compose --env-file .env.docker.local --profile graph down --timeout 210
```

The start command waits for declared health checks and reports dependency
failures. Restart policies recover exited long-running containers; an unhealthy
but still running process needs investigation. Health does not certify model
accuracy, Indexer search completeness or traffic containment. Build, migration
and end-to-end container acceptance remain pending. See
[container architecture](docs/architecture/containers.md).

## Install the Python Application

The tested Windows development runtime is Python 3.12. Create and activate
a virtual environment from the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m cybertriage --version
```

Ollama must also have `qwen3:4b-instruct` and `nomic-embed-text` installed.
Run commands from the repository root unless supplying explicit data paths.

## Catalogue and Analysis Commands

Update and inspect the local event catalogue:

```powershell
python -m cybertriage catalog-update
python -m cybertriage event-lookup --event-id 4728
```

The analysis command expects populated MITRE and Microsoft Chroma collections
in `data/chroma`. Populate the enabled sources with:

```powershell
python -m cybertriage ingest --source mitre
python -m cybertriage ingest --source microsoft
```

Sources, collections, the pinned MITRE revision, Microsoft pages, and chunking
settings are loaded from `config/sources.yaml`. Disabled sources are excluded
from retrieval and cannot be ingested. Use `--sources-config PATH` with
`analyze`, `ingest`, or `catalog-update` to select another configuration file.

Once both collections are populated:

```powershell
python -m cybertriage analyze --evidence examples/alerts/privilege-change.txt --event-id 4728 --provider Microsoft-Windows-Security-Auditing --channel Security --output data/reports/privilege-change.json
```

Only supply event metadata actually present in the incident input. An unknown
event has no catalogue definition. The model is instructed to preserve unknowns
and use supplied references, but its reasoning and citations are not automatically
certified. Empty or unfinished generation fails without an automatic retry.

`--output` saves the report text and source metadata in an application JSON file;
the model itself is not required to generate JSON. `--model` or the
`CYBERTRIAGE_MODEL` environment variable can select an already installed model.
These commands do not download model weights.

## Configuration and Response Policy

- `config/sources.yaml`: source enablement, pinned revision, document pages,
  catalogue URL, collection names, and chunking settings.
- `config/response_actions.yaml`: execution enablement, action allowlist,
  approved target identifiers, required parameters, approval lifetime, duration
  limits, and protected networks.
- `config/triage.yaml`: pre-analysis suppression exceptions, severity overrides,
  protected events, and candidate-group limits.
- `config/windows-authentication-codes.json`: sourced code definitions supplied
  with authentication evidence; unknown codes remain unresolved.

`protected_networks` is an operator-defined list of CIDRs. Private lab networks
are not automatically exempt from blocking. An empty list adds no CIDR-based
exclusions; the policy still enforces approval, targets, parameters and duration.
The example configuration currently protects only loopback/link-local ranges.
These rules affect response eligibility, not model generation or investigation.

Keep the existing collection names when reusing the current index. When changing
the MITRE revision or chunking policy, use new collection names and ingest them
before analysis; obsolete versions are not automatically removed.

Preview policy eligibility without creating approval or executing anything:

```powershell
python -m cybertriage response-policy --case-id CASE-1 --action block_ip --target lab-firewall --parameters-file examples/actions/block-ip.json
```

The JSON file supplies example action parameters, not model output or policy
configuration. `lab-firewall` is a logical target identifier; no firewall
connection is configured by this example. Execution is disabled by default.
The preview always lacks analyst approval. Its optional `--disposition` argument
is a what-if input, not a stored case-review decision.

The policy binds approval to the exact case, action, target, and parameters.
Changing those fields changes the proposal fingerprint. The persisted workflow
also binds approval to case/evidence and policy/target revisions. Adding YAML
cannot create an arbitrary command: an action needs a registered parameter
validator and allowlisted executor. See the backend workflow section below.

See [architecture](docs/architecture.md) for the ports-and-adapters boundaries.

Generate reports for manual evaluation (CPU inference can take several minutes):

```powershell
python -m cybertriage.entrypoints.evaluation --output data/evaluations/latest.json
```

The JSON records execution completion/failure and retains text reports for manual
semantic review. Completion is not a claim of error-free investigation.
Generated reports and downloaded data remain under the ignored `data/` folder.

## Local Model Setup

The initial model tests use Ollama on the Windows host, outside the Wazuh VM.

1. Install [Ollama for Windows](https://ollama.com/download/windows).
2. Check the installed version:

   ```powershell
   ollama --version
   ```

3. Download the selected candidate, approximately 2.5 GB:

   ```powershell
   ollama pull qwen3:4b-instruct
   ```

6. Start a manual test with timing statistics:

   ```powershell
   ollama run qwen3:4b-instruct --verbose
   ```

   Paste the [baseline prompt](examples/prompts/ssh-baseline.txt).
   Enter `/bye` to leave the chat. Use a fresh conversation for each independent test.

Ollama exposes its local API at `http://localhost:11434`.
The model weights are managed by Ollama and are not stored in this repository.
The local model does not require a paid model API key. Runtime memory exceeds
the model download size and varies with context and execution settings.

Sources: [Windows setup](https://docs.ollama.com/windows),
[model details](https://ollama.com/library/qwen3:4b-instruct).

## Knowledge retrieval

Refresh source metadata for existing collections, then restart any analysis
workers. Unchanged chunks keep their IDs, text and embeddings; only metadata
is updated. Fetching sources requires internet access, and any new chunks use
the existing `nomic-embed-text` embedding model:

```powershell
python -m cybertriage ingest --source mitre
python -m cybertriage ingest --source microsoft
```

Finish ingestion before restarting analysis. Old collections without platform
metadata remain usable, but incompatible-platform filtering requires the refresh.
No additional model or Python dependency is required.

Inspect references and ranking provenance without generating an LLM report:

```powershell
python -m cybertriage retrieve --query "An account failed to log on" --event-id 4625 --provider Microsoft-Windows-Security-Auditing --channel Security --k 3 --output data/evaluations/retrieval-4625.json
```

Ollama must serve the existing embedding model for semantic searches; Wazuh and
the Indexer are not required. `--platform windows|linux|macos` supplies explicit
host context when no event identity is available. `--database` and
`--sources-config` select the configured collections. Retrieval scores are
ranking heuristics, not confidence in an incident finding.

Offline checks use in-memory substitutes and need neither Ollama nor Chroma data:

```powershell
python scripts/validate_retrieval.py
```

See [ranking, snapshots and provenance](docs/architecture/retrieval.md).

### Live public documentation

`config/sources.yaml` now enables identifier-based live retrieval from Microsoft
Learn and MITRE ATT&CK. Event identities and technique IDs select approved
documentation routes; incident text is not submitted to an internet search API.
Public snapshots are cached under `data/cache/live-web.sqlite3`, with TTL,
conditional refresh, bounded stale fallback and source provenance in reports.

```powershell
python -m cybertriage retrieve --query "T1098.007 account group changes" --platform windows --output data/evaluations/live-knowledge.json
python -m cybertriage retrieve --query "An account was disabled" --event-id 4725 --provider Microsoft-Windows-Security-Auditing --channel Security --output data/evaluations/live-event-4725.json
```

These commands require the configured local collections and embedding service.
Cache misses/refreshes additionally require direct public HTTPS access. Source
errors preserve local context with visible diagnostics; they do not demonstrate
an absence of incident activity. Live references include fetch/validation times,
content hashes and explicit stale labels.

Use `--offline-knowledge` on `retrieve`, `analyze`, `analyze-stored` or `worker`
to use the static local corpus without live/cache augmentation. Set
`live_web.enabled: false` to disable it through configuration. Restart running
workers after changes. No additional model, browser, dependency or search key
is needed.

```powershell
python scripts/validate_live_web.py
```

The validation script uses isolated caches and fake HTTP/DNS; it needs neither
internet access nor Ollama. See [live retrieval design and limits](docs/architecture/live-web.md).

## Investigation search connection

Set these environment variables in the terminal running CyberTriage:

| Variable | Value |
|----------|-------|
| CYBERTRIAGE_INDEXER_URL | HTTPS Indexer origin whose hostname matches its certificate |
| CYBERTRIAGE_INDEXER_USERNAME | Dedicated read-only Indexer username |
| CYBERTRIAGE_INDEXER_CA_BUNDLE | Absolute path to the trusted CA bundle |
| CYBERTRIAGE_INDEXER_PASSWORD | Optional; otherwise the interactive CLI prompts securely |

The CLI loads optional local configuration from `.env.local` in the current
working directory. Existing environment variables take precedence. Variable
interpolation is disabled so password values are not expanded.

Store local credentials in this ignored file; do not commit passwords.
`.env.example` may contain placeholders for sharing configuration structure.

Inspect command usage with:
`python -m cybertriage search-authentication --help`
and `python -m cybertriage search-events --help`.

Searches require explicit timezone-aware start and end timestamps.
Live searches require the Indexer to be reachable.

### Related host events

Search account changes, group changes or process activity on an exact manager
and agent. This operator command uses the Indexer directly; Ollama is not needed:

```powershell
python -m cybertriage search-events --source-instance wazuh-server --agent-id 001 --family account_changes --start "2026-11-25T00:00:00Z" --end "2026-11-26T00:00:00Z" --limit 5
```

Replace the manager, agent and interval with the investigation's actual scope.
Families are `all`, `authentication`, `account_changes`, `group_changes` and
`process_activity`. `all` also supports non-Windows host alerts. Optional
`--account`/`--domain`, `--source-ip`, `--process-guid` and `--logon-id` narrow
the results. Use `--output PATH` to save the result.

The response preserves source IDs and field roles, actual search filters,
truncation and coverage. It searches indexed alerts, not complete event logs;
empty results do not prove an absence of activity. Results are candidate
context, not automatic case attachments or confirmed relationships.

Workers and `analyze-stored --investigate` now register both
`search_authentication` and `search_related_events`. The stored-alert planner
supplies the related tool's exact manager/agent and event-relative interval.
Restart existing workers to load the additional capability.

Offline checks require neither the Indexer nor Ollama:

```powershell
python scripts/validate_related_events.py
```

See [related-event profiles, filters and authority](docs/architecture/related-events.md).

## Read-only investigation

Add `--investigate` and an explicit `--task` to `analyze` to enable bounded
read-only investigation. `--task` is required in investigation mode and is
rejected without `--investigate`. Tasks are limited to 4,000 UTF-8 bytes.
The command requires the configured Indexer connection and credentials,
populated knowledge collections, and the configured models available in Ollama.

Evidence or analyst instructions must supply the account, domain, and
timezone-aware investigation window. The analyst task is passed separately
from the evidence file; instructions embedded in logs are treated as data.
The model may request up to two tools. Saved JSON reports include the task
and tool execution records. The CLI displays each
recorded tool's name, status, and call ID.

For related-event searches from a file-based analysis, also supply
`--source-instance`, `--agent-id`, `--start` and `--end`. These CLI arguments
authorize the host/time scope independently of evidence text. Add `--account`
and `--domain` together if authentication searches are also required in that
scope. Without host/time authority, the related tool returns `scope_required`;
the existing analyst-directed authentication workflow remains available.

```powershell
python -m cybertriage analyze --evidence examples/alerts/authentication-investigation.txt --event-id 4625 --provider Microsoft-Windows-Security-Auditing --channel Security --investigate --task "Call search_authentication for account zguertaoui in domain CORP from 2026-09-01T02:24:50Z inclusive to 2026-09-01T02:25:00Z exclusive, limit 5. Use the returned evidence to explain the failed logon and state remaining uncertainty." --output data/reports/authentication-investigation.json
```

The evidence file contains a recorded failed-logon event. The command supplies
the analyst search request through --task. Inspect `tool_executions` in the
saved report to distinguish
successful searches from errors or a run without tool calls. A completed report
does not by itself verify successful evidence retrieval.

Investigation does not authorize or execute response actions.

For a stored alert or queued job, enable application-generated scoped investigation:

```powershell
python -m cybertriage analyze-stored --record-id ALERT_RECORD_ID --investigate --output data/reports/stored-investigation.json
python -m cybertriage worker --once --job-id JOB_ID --investigate
```

The worker defaults to ordinary analysis. In investigation mode, the application
selects a complete structured account/domain and a bounded event-relative time
window. Each tool request is checked against that per-job scope before reaching
the Indexer. Missing identities permit no authentication searches. The saved
result includes the generated task, scope snapshot, and tool execution records.

Use an eligible pending job for a targeted worker check; completed jobs are not
reset. Continuous `worker --investigate` processes eligible queued jobs with the
same per-job limits. Non-interactive workers require the Indexer password in
environment configuration. Keep the Indexer connection/tunnel available for live
searches. See [background investigations](docs/architecture/background-worker.md).

## Documentation

### Triage and resource control

`config/triage.yaml` configures pre-analysis decisions. The default retains all
alerts, enables bounded grouping of matching Windows failed logons, and contains
no suppression rules. Unknown alerts receive individual analysis. Rules based
only on a private IP, loopback, or a failed logon are not automatically created.

The API accepts `--triage-config PATH`. Restart the API and worker after updating
code/configuration. Storage initialization adds audit/group/feedback tables;
back up the SQLite file before deployment. Existing queued jobs remain scheduled.

```powershell
python -m cybertriage triage-policy
python -m cybertriage triage-inspect --record-id ALERT_RECORD_ID
python -m cybertriage triage-feedback --record-id ALERT_RECORD_ID --analyst ANALYST_ID --label uncertain --reason "Authorization evidence has not yet been retrieved."
python -m cybertriage triage-release --record-id ALERT_RECORD_ID --analyst ANALYST_ID --reason "Additional investigation requested."
python -m cybertriage triage-evaluate --output data/evaluations/triage-quality.json
```

Feedback is append-only. Benign labels do not create suppression rules or cancel
jobs. Malicious/uncertain labels release previously unscheduled alerts for
individual analysis. Existing jobs/reports are not overwritten. Operator commands
require local database access; the analyst argument is audit metadata rather than
authenticated identity.

Evaluation reports label coverage and per-policy suppression rates; missing
labels are not treated as benign and zero-denominator rates are null. It measures
reviewed scheduling decisions rather than comprehensive attack detection accuracy.

See [triage architecture](docs/architecture/triage.md) and the
[validation guide](docs/validation/triage.md).

### Incident cases

Create a case and attach existing alert **record IDs** from the local database.
These are CyberTriage record IDs, not Wazuh source IDs. Replace the example IDs
with retained alerts. The commands below use PowerShell:

```powershell
$alertA = "ALERT_RECORD_ID_A"
$alertB = "ALERT_RECORD_ID_B"
$incident = python -m cybertriage case-create --title "Account activity investigation" --actor analyst --priority high | ConvertFrom-Json
python -m cybertriage case-attach --case-id $incident.case_id --alert-id $alertA --alert-id $alertB --actor analyst --reason "Review these alerts together."
python -m cybertriage case-note --case-id $incident.case_id --actor analyst --text "Requested account owner confirmation through a trusted channel."
python -m cybertriage case-timeline --case-id $incident.case_id
python -m cybertriage case-investigations --case-id $incident.case_id
```

An existing triage group can be attached with `--group-id GROUP_ID` instead of
`--alert-id`. This takes a snapshot; later group members are not added silently.
Reports covering attached input alerts are linked automatically when saved,
and matching historic reports are linked during attachment.

Use an observed relationship only when its structured evidence check passes:

```powershell
python -m cybertriage case-relate --case-id $incident.case_id --source-alert-id $alertA --target-alert-id $alertB --kind observed --predicate shares_host --actor analyst --reason "Both alerts report the same manager and agent."
$hypothesis = python -m cybertriage case-relate --case-id $incident.case_id --source-alert-id $alertA --target-alert-id $alertB --kind hypothesis --predicate possible_related_activity --supporting-alert-id $alertA --supporting-alert-id $alertB --actor analyst --reason "Possible connection requiring additional session evidence." | ConvertFrom-Json
$current = python -m cybertriage case-show --case-id $incident.case_id | ConvertFrom-Json
python -m cybertriage case-review-relationship --case-id $incident.case_id --relationship-id $hypothesis.relationship_id --expected-version $current.version --decision accepted --actor reviewer --reason "Retain as a working hypothesis."
```

Accepting a hypothesis does not convert it into an observation or confirm
compromise. `case-update` records explicit case status/disposition changes;
confirmation requires supporting attached alerts and a reason. It never
authorizes a firewall action. Metadata updates, detachments and relationship
reviews require the latest `--expected-version`.

| Command | Purpose |
| --- | --- |
| `case-list`, `case-show`, `case-update` | Case metadata, lifecycle and explicit findings. |
| `case-attach`, `case-detach`, `case-alerts` | Retained evidence and membership history. |
| `case-note`, `case-history` | Append-only investigation notes and workflow audit. |
| `case-relate`, `case-review-relationship`, `case-relationships` | Evidence-checked observations and separately reviewed hypotheses. |
| `case-timeline` | Chronological evidence, reports and workflow events. |
| `case-investigations`, `case-report` | Saved reports, tool history and exact input alert coverage. |

Every case command supports `--alerts-database PATH`; the default is
`data/alerts/alerts.sqlite3`. Read commands support bounded pagination; use
`--help` for their options. Actor names are local audit metadata, not login
credentials. The separate analyst API uses authenticated per-analyst credentials
and case permissions. The React application accepts those credentials in page
memory; password login and identity-provider sessions are not implemented.
Optional graph projection is described below.

Offline validation, without the VMs or Ollama:

```powershell
python scripts/validate_cases.py
```

See [case architecture and evidence rules](docs/architecture/cases.md).

### Case graphs

Export a retained case graph without Neo4j, Ollama or the VMs. Choose a new
output filename; the command does not overwrite existing files:

```powershell
python -m cybertriage graph-export --case-id $incident.case_id --output data/case-graph.json
```

The graph includes source alerts, reported entities, reviewed relationships,
chronology, report pointers and all seven Cyber Kill Chain stages. Unassessed
stages remain unassessed. An explicit stage interpretation needs active
supporting alert record IDs and the current case version:

```powershell
$current = python -m cybertriage case-show --case-id $incident.case_id | ConvertFrom-Json
# Choose the stage and reason from actual evidence; this is only a working hypothesis.
$assessment = python -m cybertriage case-stage-add --case-id $incident.case_id --stage actions_on_objectives --kind hypothesis --supporting-alert-id $alertA --expected-version $current.version --actor analyst --reason "Evidence may support this objective; further investigation required." | ConvertFrom-Json
python -m cybertriage case-stages --case-id $incident.case_id
```

`case-stage-review` appends a review using `--assertion-id`, `--decision`,
`--expected-version`, `--actor` and `--reason`. Acceptance preserves the assessment
kind; it does not confirm compromise or authorize a response.

To publish to an existing Neo4j server, install the optional official driver
in the project environment:

```powershell
python -m pip install -e ".[graph]"
```

Add the connection values to ignored `.env.local` (replace placeholders):

```dotenv
CYBERTRIAGE_NEO4J_URI=bolt://127.0.0.1:7687
CYBERTRIAGE_NEO4J_USERNAME=cybertriage_projection
CYBERTRIAGE_NEO4J_PASSWORD="REPLACE_WITH_PASSWORD"
CYBERTRIAGE_NEO4J_DATABASE=neo4j
CYBERTRIAGE_GRAPH_NAMESPACE=cybertriage
```

Remote servers require verified TLS: `neo4j+s://HOST:7687` or `bolt+s://HOST:7687`.
The password can be omitted for a hidden interactive prompt. Initialize the
constraint with a suitably privileged account, then publish with the projection
account. Explicit sync publishes the selected case; the optional worker publishes
changed versions continuously:

```powershell
python -m cybertriage graph-schema
python -m cybertriage graph-sync --case-id $incident.case_id
python -m cybertriage graph-worker
python scripts/validate_case_graph.py
```

Neo4j Browser can show the projected case after setting its case ID parameter:

```cypher
:param caseId => 'CASE_ID'
MATCH (a:CTGraphNode)-[r]->(b:CTGraphNode)
WHERE a.case_id = $caseId AND a:CTCase AND a.namespace = 'cybertriage'
RETURN a, r, b LIMIT 200;
```

For stage assessments, expand `CT_HAS_STAGE_ASSESSMENT` and `CT_ASSESSES_STAGE`.
`CT_FRAMEWORK_NEXT` is reference order, while `CT_NEXT_REPORTED_TIME` is source
chronology; neither establishes an attacker path. SQLite remains authoritative.
See [graph semantics, limits and security](docs/architecture/graph.md).

### Analyst backend and response workflow

The backend now supports case review, queued additional investigations, graph
reads and persisted response proposals/approvals through a separate analyst API.
The current firewall adapter is OPNsense. `FirewallGateway` and `ActionExecutor`
are the extension points for other vendors; FortiGate/pfSense drivers are not
implemented yet. The analyst web interface is a separate component.

Create ignored deployment configuration from the shipped templates:

```powershell
Copy-Item config/analysts.yaml config/analysts.local.yaml
Copy-Item config/firewalls.yaml config/firewalls.local.yaml
Copy-Item config/response_actions.yaml config/response_actions.local.yaml
python -m cybertriage analyst-key
```

The last command displays a random token and its SHA-256 hash. Keep the token
private; put only the hash in `config/analysts.local.yaml`. Provision separate
credentials for different analysts/roles. Example structure, with placeholders
to replace and a future UTC expiry chosen for the deployment:

```yaml
schema_version: 1
principals:
  - id: analyst-1
    token_sha256: REPLACE_WITH_GENERATED_SHA256
    permissions:
      - cases:read
      - cases:write
      - cases:review
      - investigations:request
      - reports:read_all
      - responses:propose
      - responses:approve
      - responses:execute
      - responses:reconcile
      - triage:review
    case_ids: ["*"]
    expires_at: "REPLACE_WITH_FUTURE_ISO_UTC_TIMESTAMP"
```

This example grants all listed capabilities and global evidence scope; restrict
both for each actual role. A list of explicit case IDs narrows case access.
Complete reports, related-alert discovery and new tool investigations currently
require global evidence scope because related tool results/group inputs can
extend beyond a case's attachments. API audit actors come from credentials, not
request fields. Ingestion credentials are separate.

Start the analyst API, which binds to loopback on port 8001 by default:

```powershell
python -m cybertriage serve-analyst --response-config config/response_actions.local.yaml --firewalls-config config/firewalls.local.yaml
```

For a direct non-loopback listener, supply `--tls-certificate` and `--tls-key`.
A TLS reverse proxy can instead target loopback. No wildcard CORS is enabled.
Read the authenticated schema or cases using a separately configured analyst
token in PowerShell:

```powershell
$env:CYBERTRIAGE_ANALYST_TOKEN = "REPLACE_WITH_GENERATED_TOKEN"
$headers = @{ Authorization = "Bearer $env:CYBERTRIAGE_ANALYST_TOKEN" }
Invoke-RestMethod -Uri http://127.0.0.1:8001/api/v1/me -Headers $headers
Invoke-RestMethod -Uri http://127.0.0.1:8001/api/v1/schema -Headers $headers
Invoke-RestMethod -Uri http://127.0.0.1:8001/api/v1/cases -Headers $headers
```

Use the schema for case, graph, stage, response and investigation request bodies.
The server rejects extra fields and derives the audit actor from authentication.
Permission, expiry and case-version checks are independent of model output.

#### React analyst application

The frontend is an independent application in `apps/analyst-web`, with its own
Node dependencies, build and container. FastAPI serves JSON only. During local
development the browser contacts Vite on port 5173; Vite forwards `/api/v1`
requests to the separately running analyst API on port 8001.

Use Node.js 22.12 or newer with npm. In a second PowerShell terminal:

```powershell
Set-Location apps/analyst-web
Copy-Item .env.example .env.local
npm.cmd install
npm.cmd run dev
```

Open `http://127.0.0.1:5173` and enter a provisioned analyst token. The ingestion
token cannot grant analyst access. Keep the analyst API running in its own
terminal. Investigation requests require the separate investigation worker;
opening the frontend does not start backend workers or models.

`apps/analyst-web/package-lock.json` records frontend dependencies. Review and
commit changes to it; clean installations and Docker builds use `npm ci`.
Dependencies and generated assets are excluded from Git. Full frontend
build/browser acceptance is not yet recorded.

Build the static bundle and optionally inspect it locally:

```powershell
npm.cmd run build
npm.cmd run preview
```

Preview uses port 4173 and the same configured API proxy. It is a local preview
server, not the production serving process. `ANALYST_API_UPSTREAM` in the app's
ignored `.env.local` selects the development upstream. A remote upstream requires
HTTPS with a trusted matching certificate; `NODE_EXTRA_CA_CERTS` can supply the
private CA to Node. Never put credentials in `VITE_*` variables, which become
browser-visible build settings.

For a container deployment, generate the lockfile first and supply a reachable
API origin. Example values below must match the deployment's DNS and certificate:

```powershell
Set-Location ../..
$env:ANALYST_API_UPSTREAM = "https://analyst-api.example.internal:8001"
$env:ANALYST_API_TLS_NAME = "analyst-api.example.internal"
docker compose -f apps/analyst-web/compose.yaml up --build -d
```

The frontend container binds `127.0.0.1:8080` and proxies API requests using
verified upstream TLS. A container's loopback does not reach the host API. For a
host API, use a reachable host address and configure its TLS listener or a TLS
reverse proxy; `host.docker.internal` is available to the container but still
needs matching certificate/trust configuration. Keep browser traffic on local
loopback or terminate HTTPS at the deployment ingress before exposing it remotely.

For a private API CA, add an ignored `config/analyst-web.local.yaml` override
with a read-only certificate mount (replace the host path):

```yaml
services:
  analyst-web:
    volumes:
      - "C:/deployment/certs/root-ca.pem:/etc/cybertriage/api-ca.pem:ro"
    environment:
      ANALYST_API_CA_FILE: /etc/cybertriage/api-ca.pem
```

Include that override as a second `-f config/analyst-web.local.yaml` argument to
the compose command. No firewall keys, Indexer passwords or model credentials
belong in the frontend. See [frontend architecture](docs/architecture/analyst-web.md)
for component boundaries, session handling and workflow limits.

#### Additional investigations and related-alert candidates

For an existing open case with an attached alert, queue an additional investigation
without overwriting its automatic job or previous report:

```powershell
$current = python -m cybertriage case-show --case-id $incident.case_id | ConvertFrom-Json
$request = python -m cybertriage request-investigation --case-id $incident.case_id --alert-id $alertA --expected-version $current.version --actor analyst --idempotency-key review-001 --task "Check related authentication and account activity; separate observed facts from hypotheses." | ConvertFrom-Json
python -m cybertriage investigation-worker --once --job-id $request.job_id
python -m cybertriage investigation-status --case-id $incident.case_id --job-id $request.job_id
```

Use `investigation-worker` without `--once` for continuous requested work.
Non-interactive investigation workers need the existing read-only Indexer
environment settings/password. The analyst objective cannot expand the
application-generated query scope or tool budget.

Inspect retained-alert coincidences before deciding to attach more evidence:

```powershell
python -m cybertriage case-candidates --case-id $incident.case_id --anchor-alert-id $alertA --window-seconds 300 --limit 20
```

Candidates preserve host/account field roles, evidence hashes and time distance.
Shared fields and temporal proximity do not prove the same attacker or a causal
sequence. Discovery does not change case membership or disposition.

#### OPNsense target setup

In OPNsense, create an enabled **External (advanced)** alias dedicated exclusively
to CyberTriage, such as `CyberTriageBlock`. Configure an appropriate blocking rule
referencing that alias on the actual traffic path. Provision a dedicated API
key/secret with the required alias-read/update privileges. Appliance ACLs may be
broader than one alias; the adapter restricts its own operations to the configured
container. See the official [alias documentation](https://docs.opnsense.org/manual/aliases.html).

Configure the deployment binding in `config/firewalls.local.yaml`:

```yaml
schema_version: 1
targets:
  lab-firewall:
    driver: opnsense
    base_url: https://opnsense.example.internal
    alias: CyberTriageBlock
    ca_bundle: C:/CyberTriage/certs/opnsense-root-ca.pem
    api_key_env: CYBERTRIAGE_OPNSENSE_API_KEY
    api_secret_env: CYBERTRIAGE_OPNSENSE_API_SECRET
    exclusive_alias: true
    application_managed_expiry: true
```

Use an existing absolute CA file path, or `system` for a publicly/system-trusted
certificate. The configured hostname/IP must match the certificate. Put actual
credentials in ignored `.env.local` or the service environment:

```dotenv
CYBERTRIAGE_OPNSENSE_API_KEY="REPLACE_WITH_KEY"
CYBERTRIAGE_OPNSENSE_API_SECRET="REPLACE_WITH_SECRET"
```

Only named targets allowed by response policy can be selected. Execution stays
disabled in the shipped response configuration. Enable it deliberately in the
deployment policy only when the configured lab integration is ready for acceptance.
Do not treat a model recommendation as a confirmed case finding.

OPNsense alias operations do not supply a per-address TTL. This integration
therefore uses an application-managed expiry worker. **An application/worker
outage or laptop sleep can extend a block's duration.** The two explicit target
flags acknowledge exclusive alias ownership and this expiry contract; they do
not create a native device expiry guarantee. Keep the worker on a reliable host:

```powershell
python -m cybertriage response-expiry-worker --config config/response_actions.local.yaml --firewalls-config config/firewalls.local.yaml
```

Run the expiry worker while leases exist, including after disabling new execution.
Do not manually share this alias with another writer. The adapter does not flush
tables, modify arbitrary rules or clear established firewall states. It records
observed alias membership separately from verified traffic blocking.

#### Propose, review and execute

The case must be open and have a supported, evidence-backed confirmed-compromise
finding before approval. Both the policy and target must be configured. The
following operations are separate; proposal/review never dispatch implicitly:

```powershell
$current = python -m cybertriage case-show --case-id $incident.case_id | ConvertFrom-Json
$proposal = python -m cybertriage response-propose --config config/response_actions.local.yaml --firewalls-config config/firewalls.local.yaml --case-id $incident.case_id --expected-version $current.version --action block_ip --target lab-firewall --parameters-file examples/actions/block-ip.json --supporting-alert-id $alertA --idempotency-key block-001 --actor analyst --reason "Contain the address supported by the reviewed evidence." | ConvertFrom-Json
python -m cybertriage response-review --config config/response_actions.local.yaml --firewalls-config config/firewalls.local.yaml --proposal-id $proposal.proposal_id --expected-version $proposal.current_case_version --decision approved --actor reviewer --reason "Reviewed the exact target, address, duration and evidence."
```

Refresh the stored proposal before explicit execution:

```powershell
$approved = python -m cybertriage response-show --config config/response_actions.local.yaml --firewalls-config config/firewalls.local.yaml --proposal-id $proposal.proposal_id | ConvertFrom-Json
python -m cybertriage response-execute --config config/response_actions.local.yaml --firewalls-config config/firewalls.local.yaml --proposal-id $proposal.proposal_id --expected-version $approved.current_case_version --actor responder --reason "Execute the current authorized proposal."
```

Case, evidence, policy or target changes invalidate existing authority. Expired
or stale proposals need a fresh proposal/review. One proposal has at most one
dispatch claim; a lost response is resolved by reading its state, not retrying
the mutation. `unknown`/abandoned outcomes require stopping the original process,
checking the appliance and using `response-reconcile` or
`response-release-reconcile` with verified evidence. Never mark absence or
success from a timeout alone.

For single-host process operation, backups and unresolved-action handling see
[operations](docs/operations.md), [response lifecycle](docs/architecture/response-workflow.md)
and [analyst API](docs/architecture/analyst-api.md). Functional and live-device
acceptance remain pending; implemented code is not a production acceptance result.

### Project documentation

Design decisions, learning notes, experiments, and evaluation results
will be documented as the project progresses:

- [Implementation and acceptance status](docs/implementation-status.md)
- [Analysis evaluation criteria](docs/evaluation.md)
- [Architecture and trust boundaries](docs/architecture.md)
- [Live evaluation cases](config/evaluation-cases.json)
- [Baseline SSH prompt](examples/prompts/ssh-baseline.txt)

Further installation, configuration, and usage instructions will be added
to this README as the corresponding components become available.
