"""Composition root: select adapters here; keep use cases independent of them."""

import os
from pathlib import Path
from typing import Callable, TYPE_CHECKING
from dataclasses import replace

if TYPE_CHECKING:
    from cybertriage.application.services.case_management import CaseManagement
    from cybertriage.adapters.wazuh.indexer_http import WazuhIndexerHttpClient

from cybertriage.application.ports.related_events import RelatedEventSearcher
from cybertriage.application.ports.retrieval import ContextualKnowledgeRetriever

from langchain_ollama import ChatOllama
from cybertriage.adapters.configuration.ollama_environment import ollama_base_url

from cybertriage.adapters.configuration.yaml_files import (
    YamlKnowledgeConfiguration,
    YamlResponseConfiguration,
)
from cybertriage.application.services.analysis_worker import AnalysisWorker
from cybertriage.adapters.knowledge.chunking import RecursiveKnowledgeChunker
from cybertriage.application.services.knowledge_retrieval import HybridKnowledgeRetriever
from cybertriage.adapters.knowledge.sources.microsoft import MicrosoftEventSource
from cybertriage.adapters.knowledge.sources.mitre import MitreSource
from cybertriage.adapters.models.embeddings import RunbookEmbeddings
from cybertriage.adapters.models.triage import OllamaTriageModel
from cybertriage.adapters.storage.chroma import ChromaKnowledgeIndex
from cybertriage.application.policies.response_actions import (
    BlockIpParameterValidator,
    ResponseActionPolicy,
)
from cybertriage.application.ports.configuration import (
    IndexerConfigurationProvider,
    KnowledgeConfigurationProvider,
    ResponseConfigurationProvider,
)
from cybertriage.application.ports.investigation import (
    AuthenticationEventSearcher,
)
from cybertriage.application.ports.knowledge import KnowledgeSource
from cybertriage.application.use_cases.analyze_alert import AnalyzeAlert
from cybertriage.application.use_cases.ingest_knowledge import IngestKnowledge
from cybertriage.application.use_cases.preview_response_action import PreviewResponseAction
from cybertriage.domain.configuration import KnowledgeSettings
from cybertriage.domain.investigation import AuthenticationScope
from cybertriage.application.use_cases.analyze_stored_alert import (
    AnalyzeStoredAlert,
)

from cybertriage.application.ports.agent import InvestigationModel
from cybertriage.application.ports.triage_policy import TriageConfigurationProvider

DEFAULT_SOURCES_CONFIG = Path("config/sources.yaml")
DEFAULT_RESPONSE_CONFIG = Path("config/response_actions.yaml")
DEFAULT_TRIAGE_CONFIG = Path("config/triage.yaml")
DEFAULT_AUTHENTICATION_REGISTRY = Path("config/windows-authentication-codes.json")


def build_authentication_grounder():
    from cybertriage.adapters.knowledge.authentication_grounding import MicrosoftAuthenticationGrounder
    return MicrosoftAuthenticationGrounder(DEFAULT_AUTHENTICATION_REGISTRY)


def _load_knowledge(
    path: Path,
    configuration: KnowledgeConfigurationProvider | None = None,
) -> KnowledgeSettings:
    provider = configuration if configuration is not None else YamlKnowledgeConfiguration(path)
    return provider.load()


def _source_bindings(
    settings: KnowledgeSettings,
) -> dict[str, tuple[bool, str, Callable[[], KnowledgeSource]]]:
    return {
        "mitre": (
            settings.mitre.enabled,
            settings.mitre.collection_name,
            lambda: MitreSource(revision=settings.mitre.revision),
        ),
        "microsoft": (
            settings.microsoft.enabled,
            settings.microsoft.collection_name,
            lambda: MicrosoftEventSource(
                base_url=settings.microsoft.base_url,
                pages=settings.microsoft.pages,
            ),
        ),
    }


def build_knowledge_retriever(
    database_directory: Path,
    sources_config_path: Path = DEFAULT_SOURCES_CONFIG,
    configuration: KnowledgeConfigurationProvider | None = None,
    *,
    offline_knowledge: bool = False,
) -> ContextualKnowledgeRetriever:
    settings = _load_knowledge(sources_config_path, configuration)
    if not database_directory.is_dir():
        raise FileNotFoundError(f"Knowledge database directory not found: {database_directory}")
    collections = [name for enabled, name, _ in _source_bindings(settings).values() if enabled]
    if not collections:
        raise ValueError("Enable at least one knowledge source in sources.yaml.")
    embeddings = RunbookEmbeddings()
    local = HybridKnowledgeRetriever(tuple(ChromaKnowledgeIndex(
        directory=database_directory, embeddings=embeddings, collection_name=name, create_if_missing=False,
    ) for name in collections))
    sources = tuple(source for source in settings.live_web.sources
                    if (source == "mitre" and settings.mitre.enabled) or (source == "microsoft" and settings.microsoft.enabled))
    if offline_knowledge or not settings.live_web.enabled or not sources:
        return local
    from cybertriage.adapters.knowledge.web_http import ApprovedPublicHttpFetcher
    from cybertriage.adapters.knowledge.web_parsing import OfficialDocumentationParser
    from cybertriage.adapters.storage.web_cache_sqlite import SqlitePublicDocumentCache
    from cybertriage.application.services.live_knowledge import LiveDocumentReader, LiveWebKnowledgeRetriever
    web = replace(settings.live_web, sources=sources)
    cache_path = web.cache_path.resolve()
    if not cache_path.is_relative_to(Path("data").resolve()):
        raise ValueError("Public web cache must remain under the project's data directory.")
    return LiveWebKnowledgeRetriever(local, LiveDocumentReader(SqlitePublicDocumentCache(cache_path),
        ApprovedPublicHttpFetcher(), OfficialDocumentationParser(), web),
        RecursiveKnowledgeChunker(settings.chunk_size, settings.chunk_overlap), web,
        chunk_input_limit=min(150000, 256 * (settings.chunk_size - settings.chunk_overlap)))


def build_analyze_alert(
    database_directory: Path,
    catalog_path: Path | None = None,
    model_name: str | None = None,
    sources_config_path: Path = DEFAULT_SOURCES_CONFIG,
    configuration: KnowledgeConfigurationProvider | None = None,
    *,
    investigate: bool = False,
    offline_knowledge: bool = False,
    password_supplier: Callable[[], str] | None = None,
    conversation: bool = False,
) -> AnalyzeAlert:
    retriever = build_knowledge_retriever(database_directory, sources_config_path, configuration, offline_knowledge=offline_knowledge)

    ollama = ChatOllama(
        model=model_name or os.environ.get(
            "CYBERTRIAGE_MODEL",
            "qwen3:4b-instruct",
        ),
        base_url=ollama_base_url(),
        temperature=0,
        num_ctx=8192,
        num_predict=800,
        reasoning=False,
        client_kwargs={"timeout": 180.0},
    )

    catalog = load_event_catalog(catalog_path) if catalog_path is not None else None
    investigator: InvestigationModel | None = None

    if investigate:
        from cybertriage.adapters.models.investigation import (
            OllamaInvestigationModel,
        )
        from cybertriage.adapters.tools.authentication import (
            build_authentication_search_tool,
        )

        from cybertriage.adapters.tools.related_events import build_related_event_search_tool
        from cybertriage.adapters.wazuh.authentication_search import WazuhAuthenticationEventSearcher
        from cybertriage.adapters.wazuh.related_event_search import WazuhRelatedEventSearcher
        from cybertriage.domain.related_events import InvestigationScope

        client = _build_indexer_client(password_supplier=password_supplier)
        searcher = WazuhAuthenticationEventSearcher(client)
        related_searcher = WazuhRelatedEventSearcher(client)
        authentication_grounder = build_authentication_grounder()

        def tools_for_scope(scope: AuthenticationScope | None):
            return [
                build_authentication_search_tool(searcher, grounder=authentication_grounder, scope=scope),
                build_related_event_search_tool(related_searcher, catalog=catalog,
                    scope=scope.related_events if isinstance(scope, InvestigationScope) else None),
            ]

        investigator = OllamaInvestigationModel(
            model=ollama,
            tools=tools_for_scope(None),
            scoped_tool_factory=tools_for_scope,
            conversation=conversation,
        )

    return AnalyzeAlert(
        retriever=retriever,
        model=OllamaTriageModel(ollama),
        retrieval_limit=3,
        catalog=catalog,
        investigator=investigator,
        contextual_retriever=retriever,
    )

def build_knowledge_ingestion(
    source_name: str,
    database_directory: Path,
    sources_config_path: Path = DEFAULT_SOURCES_CONFIG,
    configuration: KnowledgeConfigurationProvider | None = None,
) -> IngestKnowledge:
    settings = _load_knowledge(sources_config_path, configuration)
    bindings = _source_bindings(settings)
    if source_name not in bindings:
        raise ValueError(f"Unsupported knowledge source: {source_name}")
    enabled, collection_name, factory = bindings[source_name]
    if not enabled:
        raise ValueError(f"Knowledge source is disabled: {source_name}")
    return IngestKnowledge(
        source=factory(),
        chunker=RecursiveKnowledgeChunker(
            chunk_size=settings.chunk_size,
            chunk_overlap=settings.chunk_overlap,
        ),
        index=ChromaKnowledgeIndex(
            directory=database_directory,
            embeddings=RunbookEmbeddings(),
            collection_name=collection_name,
        ),
    )


def build_microsoft_ingestion(database_directory: Path) -> IngestKnowledge:
    return build_knowledge_ingestion("microsoft", database_directory)


def build_catalog_update(
    snapshot_path: Path,
    sources_config_path: Path = DEFAULT_SOURCES_CONFIG,
):
    from cybertriage.adapters.knowledge.sources.microsoft_catalog import MicrosoftCatalogSource
    from cybertriage.adapters.storage.event_catalog_json import JsonEventCatalogStore
    from cybertriage.application.use_cases.update_event_catalog import UpdateEventCatalog

    settings = _load_knowledge(sources_config_path)
    return UpdateEventCatalog(
        source=MicrosoftCatalogSource(url=settings.catalog_url),
        store=JsonEventCatalogStore(snapshot_path),
    )


def load_event_catalog(snapshot_path: Path):
    from cybertriage.adapters.event_catalog import MicrosoftSecurityEventCatalog
    from cybertriage.adapters.storage.event_catalog_json import JsonEventCatalogStore

    return MicrosoftSecurityEventCatalog(JsonEventCatalogStore(snapshot_path).load())


def build_response_preview(
    config_path: Path = DEFAULT_RESPONSE_CONFIG,
    configuration: ResponseConfigurationProvider | None = None,
) -> PreviewResponseAction:
    provider = configuration if configuration is not None else YamlResponseConfiguration(config_path)
    policy = ResponseActionPolicy(
        settings=provider.load(),
        validators={"block_ip": BlockIpParameterValidator()},
    )
    return PreviewResponseAction(policy)

def build_alert_ingestion(
    database_path: Path,
    triage_config_path: Path = DEFAULT_TRIAGE_CONFIG,
    *,
    configuration: TriageConfigurationProvider | None = None,
):
    from cybertriage.adapters.storage.alerts_sqlite import (
        SqliteAlertRepository,
    )
    from cybertriage.adapters.wazuh.normalizer import (
        WazuhAlertNormalizer,
    )
    from cybertriage.application.use_cases.ingest_alert import (
        IngestAlert,
    )
    from cybertriage.adapters.configuration.triage_yaml import YamlTriageConfiguration
    from cybertriage.application.policies.alert_triage import AlertTriagePolicy

    provider = configuration if configuration is not None else YamlTriageConfiguration(triage_config_path)
    policy = AlertTriagePolicy(provider.load())

    return IngestAlert(
        normalizer=WazuhAlertNormalizer(),
        repository=SqliteAlertRepository(database_path, triage_policy=policy),
    )

def build_ingestion_api(
    database_path: Path,
    token: str,
    triage_config_path: Path = DEFAULT_TRIAGE_CONFIG,
):
    from cybertriage.entrypoints.api.app import create_app

    ingestion = build_alert_ingestion(database_path, triage_config_path)

    return create_app(
        ingestion=ingestion,
        token=token,
    )

def build_analyze_stored_alert(
    alerts_database_path: Path,
    database_directory: Path,
    catalog_path: Path,
    model_name: str | None = None,
    sources_config_path: Path = DEFAULT_SOURCES_CONFIG,
    *,
    investigate: bool = False,
    offline_knowledge: bool = False,
    password_supplier: Callable[[], str] | None = None,
) -> AnalyzeStoredAlert:
    from cybertriage.adapters.storage.alerts_sqlite import (
        SqliteAlertRepository,
    )
    from cybertriage.adapters.storage.analyses_sqlite import (
        SqliteAnalysisWriter,
    )

    if not alerts_database_path.is_file():
        raise FileNotFoundError(
            f"Alert database not found: {alerts_database_path}"
        )

    reader = SqliteAlertRepository(alerts_database_path)
    writer = SqliteAnalysisWriter(alerts_database_path)
    from cybertriage.adapters.storage.triage_sqlite import SqliteTriageReviewRepository
    grounder = build_authentication_grounder()
    from cybertriage.application.policies.stored_investigation import ReadOnlyStoredInvestigationPlanner

    return AnalyzeStoredAlert(
        reader=reader,
        analyzer=build_analyze_alert(
            database_directory=database_directory,
            catalog_path=catalog_path,
            model_name=model_name,
            sources_config_path=sources_config_path,
            investigate=investigate,
            offline_knowledge=offline_knowledge,
            password_supplier=password_supplier,
        ),
        writer=writer,
        group_reader=SqliteTriageReviewRepository(alerts_database_path, grounder=grounder),
        grounder=grounder,
        investigation_planner=ReadOnlyStoredInvestigationPlanner() if investigate else None,
    )

def build_analysis_worker(
    alerts_database_path: Path,
    database_directory: Path,
    catalog_path: Path,
    model_name: str | None = None,
    sources_config_path: Path = DEFAULT_SOURCES_CONFIG,
    *,
    lease_seconds: int = 600,
    max_attempts: int = 3,
    retry_delay_seconds: int = 30,
    poll_seconds: float = 2.0,
    investigate: bool = False,
    offline_knowledge: bool = False,
    password_supplier: Callable[[], str] | None = None,
) -> AnalysisWorker:
    from cybertriage.adapters.storage.alerts_sqlite import (
        SqliteAlertRepository,
    )
    from cybertriage.adapters.storage.analyses_sqlite import (
        SqliteAnalysisWriter,
    )
    from cybertriage.adapters.storage.jobs_sqlite import (
        SqliteAnalysisQueue,
    )
    from cybertriage.application.use_cases.process_analysis_job import (
        ProcessAnalysisJob,
    )

    if not alerts_database_path.is_file():
        raise FileNotFoundError(
            f"Alert database not found: {alerts_database_path}. "
            "Start the ingestion API first."
        )

    reader = SqliteAlertRepository(alerts_database_path)

    # Initialize the analyses table before opening job-result storage.
    SqliteAnalysisWriter(alerts_database_path)

    queue = SqliteAnalysisQueue(alerts_database_path)
    from cybertriage.adapters.storage.triage_sqlite import SqliteTriageReviewRepository
    grounder = build_authentication_grounder()
    from cybertriage.application.policies.stored_investigation import ReadOnlyStoredInvestigationPlanner

    processor = ProcessAnalysisJob(
        reader=reader,
        analyzer=build_analyze_alert(
            database_directory=database_directory,
            catalog_path=catalog_path,
            model_name=model_name,
            sources_config_path=sources_config_path,
            investigate=investigate,
            offline_knowledge=offline_knowledge,
            password_supplier=password_supplier,
        ),
        completer=queue,
        group_reader=SqliteTriageReviewRepository(alerts_database_path, grounder=grounder),
        grounder=grounder,
        investigation_planner=ReadOnlyStoredInvestigationPlanner() if investigate else None,
    )

    return AnalysisWorker(
        claimer=queue,
        renewer=queue,
        failures=queue,
        processor=processor,
        lease_seconds=lease_seconds,
        max_attempts=max_attempts,
        retry_delay_seconds=retry_delay_seconds,
        poll_seconds=poll_seconds,
    )

def build_authentication_search(
    configuration: IndexerConfigurationProvider | None = None,
    password_supplier: Callable[[], str] | None = None,
) -> AuthenticationEventSearcher:
    from cybertriage.adapters.wazuh.authentication_search import (
        WazuhAuthenticationEventSearcher,
    )
    return WazuhAuthenticationEventSearcher(_build_indexer_client(configuration, password_supplier))


def build_related_event_search(
    configuration: IndexerConfigurationProvider | None = None,
    password_supplier: Callable[[], str] | None = None,
) -> RelatedEventSearcher:
    from cybertriage.adapters.wazuh.related_event_search import WazuhRelatedEventSearcher
    return WazuhRelatedEventSearcher(_build_indexer_client(configuration, password_supplier))


def _build_indexer_client(
    configuration: IndexerConfigurationProvider | None = None,
    password_supplier: Callable[[], str] | None = None,
) -> "WazuhIndexerHttpClient":
    from cybertriage.adapters.configuration.indexer_environment import EnvironmentIndexerConfiguration
    from cybertriage.adapters.wazuh.indexer_http import (
        WazuhIndexerHttpClient,
    )

    provider = (
        configuration
        if configuration is not None
        else EnvironmentIndexerConfiguration()
    )
    settings = provider.load()

    password = os.environ.get("CYBERTRIAGE_INDEXER_PASSWORD")

    if not password and password_supplier is not None:
        password = password_supplier()

    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        raise ValueError("A valid Indexer password is required.")

    return WazuhIndexerHttpClient(
        base_url=settings.base_url,
        username=settings.username,
        password=password,
        ca_bundle=settings.ca_bundle,
    )


def build_triage_review(database_path: Path):
    from cybertriage.adapters.storage.triage_sqlite import SqliteTriageReviewRepository
    from cybertriage.application.services.triage_review import ReviewTriage
    return ReviewTriage(SqliteTriageReviewRepository(database_path))


def build_triage_evaluation(database_path: Path):
    from cybertriage.adapters.storage.triage_sqlite import SqliteTriageReviewRepository
    from cybertriage.application.services.triage_review import EvaluateTriage
    return EvaluateTriage(SqliteTriageReviewRepository(database_path))


def build_case_management(database_path: Path) -> "CaseManagement":
    """Compose the local case service without loading models or network clients."""
    from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
    from cybertriage.application.policies.case_relationships import ObservedRelationshipPolicy
    from cybertriage.application.services.case_management import CaseManagement

    return CaseManagement(SqliteCaseRepository(database_path), ObservedRelationshipPolicy())


def build_response_runtime(database_path: Path, response_config: Path = DEFAULT_RESPONSE_CONFIG,
                           firewalls_config: Path = Path("config/firewalls.yaml")):
    from dataclasses import asdict
    from hashlib import sha256
    from cybertriage.adapters.configuration.firewall_yaml import YamlFirewallConfiguration
    from cybertriage.adapters.opnsense import OpnsenseFirewallGateway
    from cybertriage.adapters.storage.responses_sqlite import SqliteResponseRepository
    from cybertriage.application.services.block_ip import ExpireIpBlocks, ManagedIpBlockExecutor
    from cybertriage.application.services.response_workflow import ResponseWorkflow
    from cybertriage.domain.response_workflow import ResponsePolicySnapshot, canonical

    # New vendor adapters register here; proposal/review/execution services remain unchanged.
    providers = {"opnsense": OpnsenseFirewallGateway}
    targets = YamlFirewallConfiguration(firewalls_config, tuple(providers)).load()
    revision = sha256(canonical([asdict(target) for target in targets]).encode()).hexdigest()
    gateways = {target.name: providers[target.driver](target) for target in targets}
    repository = SqliteResponseRepository(database_path)
    snapshot = ResponsePolicySnapshot(YamlResponseConfiguration(response_config).load(), revision)
    workflow = ResponseWorkflow(repository, snapshot,
        {("block_ip", name): ManagedIpBlockExecutor(gateway) for name, gateway in gateways.items()})
    return workflow, ExpireIpBlocks(repository, gateways, revision), repository


def build_requested_investigation_worker(alerts_database_path: Path, database_directory: Path,
                                         catalog_path: Path, sources_config_path: Path = DEFAULT_SOURCES_CONFIG,
                                         *, model_name: str | None = None, offline_knowledge: bool = False):
    from cybertriage.adapters.storage.investigation_requests import SqliteInvestigationRequests
    from cybertriage.adapters.storage.alerts_sqlite import SqliteAlertRepository
    from cybertriage.adapters.storage.triage_sqlite import SqliteTriageReviewRepository
    from cybertriage.application.services.requested_investigation import ProcessRequestedInvestigation

    queue = SqliteInvestigationRequests(alerts_database_path)
    grounder = build_authentication_grounder()
    processor = ProcessRequestedInvestigation(queue, SqliteAlertRepository(alerts_database_path),
        build_analyze_alert(database_directory, catalog_path, model_name, sources_config_path,
            investigate=True, offline_knowledge=offline_knowledge), grounder,
        SqliteTriageReviewRepository(alerts_database_path, grounder=grounder))
    return AnalysisWorker(claimer=queue, renewer=queue, failures=queue, processor=processor)


def build_case_stages(database_path: Path):
    from cybertriage.adapters.storage.case_stages_sqlite import SqliteCaseStageRepository
    from cybertriage.application.services.case_stages import CaseStages

    return CaseStages(SqliteCaseStageRepository(database_path))


def build_case_graph_export(database_path: Path, namespace: str = "cybertriage"):
    from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
    from cybertriage.adapters.storage.case_graph_sqlite import SqliteCaseGraphReader
    from cybertriage.application.services.case_graph import CaseGraphBuilder, ExportCaseGraph

    # Additive local schema migration precedes the separate read-only snapshot connection.
    SqliteCaseRepository(database_path)
    reader = SqliteCaseGraphReader(database_path)
    return ExportCaseGraph(reader, CaseGraphBuilder(), namespace)


def build_case_graph_projection(database_path: Path, sink, namespace: str = "cybertriage"):
    from cybertriage.adapters.storage.case_graph_sqlite import SqliteCaseGraphReader
    from cybertriage.application.services.case_graph import ProjectCaseGraph

    return ProjectCaseGraph(build_case_graph_export(database_path, namespace), SqliteCaseGraphReader(database_path), sink)



def build_case_conversation(database_path: Path):
    from cybertriage.adapters.storage.case_chat_sqlite import SqliteCaseChat
    from cybertriage.application.services.case_chat import CaseConversation
    store = SqliteCaseChat(database_path)
    return CaseConversation(store), store


def build_case_chat_worker(database_path: Path, database_directory: Path, catalog_path: Path,
                           sources_config_path: Path = DEFAULT_SOURCES_CONFIG,
                           *, model_name: str | None = None, offline_knowledge: bool = False):
    from cybertriage.adapters.storage.case_chat_sqlite import SqliteCaseChat
    from cybertriage.adapters.storage.alerts_sqlite import SqliteAlertRepository
    from cybertriage.application.services.case_chat import ProcessCaseChat
    from cybertriage.application.services.case_chat_worker import CaseChatWorker
    queue = SqliteCaseChat(database_path)
    processor = ProcessCaseChat(queue, SqliteAlertRepository(database_path),
        build_analyze_alert(database_directory, catalog_path, model_name, sources_config_path,
                            investigate=True, conversation=True, offline_knowledge=offline_knowledge),
        build_authentication_grounder())
    return CaseChatWorker(queue, processor)
