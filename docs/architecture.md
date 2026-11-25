# Architecture and trust boundaries

CyberTriage uses ports and adapters (hexagonal architecture), with constructor
injection and factories in the composition root.

```mermaid
flowchart TD
    Sources[sources.yaml] --> Configuration[YAML configuration adapter]
    Configuration --> Bootstrap[Composition root]
    Input[Incident evidence] --> UseCase[AnalyzeAlert]
    Catalog[Local event catalogue] --> UseCase
    Chroma[Enabled source collections] --> Retrieval[Composite retriever]
    Retrieval --> UseCase
    Bootstrap --> UseCase
    UseCase --> Model[Ollama readable report]
    Model --> Completion[Nonempty text and completion checks]
    Completion --> Report[Provisional report and source metadata]
    Report --> Review[Analyst review]
    Actions[response_actions.yaml] --> Policy[Response action policy]
    Policy --> Preview[Eligibility preview only]
```

## Patterns used

- **Ports and adapters:** domain/application code is separated from integrations.
- **Dependency injection:** use cases and policies receive their collaborators.
- **Factory registry:** `bootstrap._source_bindings()` connects configured source
  names to source factories and collections.
- **Strategy:** model, retrieval, configuration and parameter-validation ports
  allow alternative implementations.
- **Composite:** `FederatedKnowledgeRetriever` combines configured retrievers.
- **Policy object:** `ResponseActionPolicy` evaluates a concrete action proposal.

These patterns are used where there is an actual boundary. Empty architecture
folders do not represent completed features.

## Runtime configuration

Ingestion applies a configurable triage policy before scheduling analysis.
Its decision, optional group membership, and job are persisted with the alert
in one transaction. Review labels are separate append-only records and never
become model-generated ground truth. See [alert triage](architecture/triage.md)
for the scheduling policy, group lifecycle, grounding registry, and evaluation.

`YamlKnowledgeConfiguration` reads `config/sources.yaml` into immutable typed
settings. Ingestion uses its revision, page list, URLs and chunking values.
Analysis uses its enabled sources and collection names. Catalogue updates use
its configured catalogue URL. Parsing rejects duplicate keys, unknown fields,
unsupported YAML tags/aliases, and invalid value types.

`YamlResponseConfiguration` reads `config/response_actions.yaml`. It configures
allowed action/target pairs, parameters, limits, protected networks and approval
lifetime. `PreviewResponseAction` calls the policy without supplying approval;
it cannot approve or execute anything.

## Readable analysis baseline

`TriageModel.analyze()` returns ordinary text. There is no required model JSON
schema, account-name substitution, generated-quote matching, or corrective loop.
A blank, non-text, or unfinished response fails visibly. These are generation
checks, not factual certification.

The prompt asks the model to separate facts, hypotheses, missing evidence,
investigation checks and conclusions. Catalogue definitions and incident event
metadata are kept distinct. Retrieved references provide background knowledge,
not additional incident facts. The report and source metadata can be saved as
application JSON without asking the model to generate JSON.

## Response boundary

Current code includes policy evaluation, not an execution backend. Policy
configuration requires both confirmed compromise and explicit analyst approval.
Approval is bound to a fingerprint of the case, action, target and parameters,
and has a configured lifetime. An action must also have a registered parameter
validator. The current block-IP validator checks the address, duration and
protected networks, including IPv4-mapped address forms.

The future authenticated case-review workflow must obtain disposition and
approval from trusted stored records, not model prose or arbitrary client flags.
The CLI disposition flag is only a what-if preview. It creates no review record.
Firewall executors, persisted approvals, authentication and auditing remain to
be implemented. The model has no shell or firewall execution capability.

## Analysis validation

Generation checks verify that a response is nonempty text and has completed.
They do not establish factual accuracy, citation relevance, or investigation
quality. Reports require evaluation against the incident evidence and retrieved
sources; see [analysis evaluation](evaluation.md).
