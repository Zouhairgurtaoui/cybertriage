from cybertriage.application.ports.event_catalog import SecurityEventCatalog
from cybertriage.application.ports.triage import (
    KnowledgeRetriever,
    TriageModel,
)
from cybertriage.domain.security_event import EventIdentity
from cybertriage.domain.triage import RetrievedReference, TriageResult

from cybertriage.application.ports.agent import InvestigationModel
from cybertriage.domain.agent import ToolExecution


class AnalyzeAlert:
    def __init__(
        self,
        retriever: KnowledgeRetriever,
        model: TriageModel,
        retrieval_limit: int = 3,
        catalog: SecurityEventCatalog | None = None,
        *,
        investigator: InvestigationModel | None = None,
    ):
        if not 1 <= retrieval_limit <= 20:
            raise ValueError("retrieval_limit must be between 1 and 20.")

        self._retriever = retriever
        self._model = model
        self._retrieval_limit = retrieval_limit
        self._catalog = catalog
        self._investigator = investigator

    
    #
    def execute(
        self,
        evidence: str,
        retrieval_query: str | None = None,
        event: EventIdentity | None = None,
    ) -> TriageResult:
        evidence = evidence.strip()

        if not evidence:
            raise ValueError("Incident evidence must not be empty.")
        if len(evidence.encode("utf-8")) > 12000:
            raise ValueError("Incident evidence exceeds the application input limit.")
        if any(ord(character) < 32 and character not in "\n\r\t" for character in evidence):
            raise ValueError("Incident evidence contains unsupported control characters.")

        definition = None

        if event is not None:
            if self._catalog is None:
                raise RuntimeError(
                    "An event catalogue is required for event-aware analysis."
                )

            definition = self._catalog.lookup(
                provider=event.provider,
                channel=event.channel,
                event_id=event.event_id,
            )

        if retrieval_query is not None:
            query = retrieval_query.strip()
        elif definition is not None:
            query = definition.description
        else:
            query = evidence

        if not query:
            raise ValueError("Retrieval query must not be empty.")

        references = []

        if definition is not None:
            references.append(
                RetrievedReference(
                    chunk_id=(
                        f"catalog:{definition.source_revision}:"
                        f"{definition.provider}:{definition.channel}:"
                        f"{definition.event_id}"
                    ),
                    title=f"Windows Security event {definition.event_id}",
                    source_url=definition.source_url,
                    text=(
                        f"Provider: {definition.provider}\n"
                        f"Channel: {definition.channel}\n"
                        f"Event ID: {definition.event_id}\n"
                        f"Definition: {definition.description}\n"
                        "This definition describes the event type. "
                        "It does not establish malicious intent."
                    ),
                )
            )

        references.extend(
            self._retriever.retrieve(
                query=query,
                k=self._retrieval_limit,
            )
        )

        reference_tuple = tuple(references)

        model_evidence = evidence

        if event is not None:
            model_evidence = (
                "Event identity supplied with this incident:\n"
                f"Provider: {event.provider}\n"
                f"Channel: {event.channel}\n"
                f"Event ID: {event.event_id}\n\n"
                "Incident observations:\n"
                f"{evidence}"
            )

        tool_executions: tuple[ToolExecution, ...] = ()

        if self._investigator is None:
            analysis = self._model.analyze(
                evidence=model_evidence,
                references=reference_tuple,
            )
        else:
            investigation = self._investigator.investigate(
                evidence=model_evidence,
                references=reference_tuple,
            )
            analysis = investigation.analysis
            tool_executions = investigation.tool_executions

        if not isinstance(analysis, str) or not analysis.strip():
            raise RuntimeError(
                "The model returned an empty or non-text report."
            )

        return TriageResult(
            analysis=analysis.strip(),
            references=reference_tuple,
            event_definition=definition,
            tool_executions=tool_executions,
        )