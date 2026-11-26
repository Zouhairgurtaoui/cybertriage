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
Authenticated Wazuh ingestion, SQLite-backed background analysis, and a read-only
authentication search are implemented. The analysis CLI supports opt-in model
tool calling. There is no firewall executor or approval-storage workflow yet.
Background workers support opt-in scoped authentication investigation. The analyst
web application remains planned. See
[implementation status](docs/implementation-status.md).

Ingestion includes auditable triage and candidate grouping before job scheduling.
Operator commands support analyst feedback and suppression-quality evaluation.
Authentication results include computed search summaries and sourced code
definitions. These features require deployment validation; model reports remain
provisional.

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
Changing those fields changes the proposal fingerprint. An authenticated review
workflow and execution adapter are future components; the policy alone does not
implement them. Adding an entry to YAML cannot create an arbitrary command:
an action also needs a registered parameter validator and, later, an executor.

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

Searches require explicit timezone-aware start and end timestamps.
Live searches require the Indexer to be reachable.

## Read-only investigation

Add `--investigate` and an explicit `--task` to `analyze` to enable bounded
authentication searches. `--task` is required in investigation mode and is
rejected without `--investigate`. Tasks are limited to 4,000 UTF-8 bytes.
The command requires the configured Indexer connection and credentials,
populated knowledge collections, and the configured models available in Ollama.

Evidence or analyst instructions must supply the account, domain, and
timezone-aware investigation window. The analyst task is passed separately
from the evidence file; instructions embedded in logs are treated as data.
The model may request up to two tools. Saved JSON reports include the task
and tool execution records. The CLI displays each
recorded tool's name, status, and call ID.

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
credentials. Case HTTP access, authenticated analyst sessions and Neo4j graph
projection remain separate work.

Offline validation, without the VMs or Ollama:

```powershell
python scripts/validate_cases.py
```

See [case architecture and evidence rules](docs/architecture/cases.md).

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
