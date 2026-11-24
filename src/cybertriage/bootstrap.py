"""Composition root: select adapters here; keep use cases independent of them."""

import os
from pathlib import Path
from typing import Callable

from langchain_ollama import ChatOllama

from cybertriage.adapters.configuration.yaml_files import (
    YamlKnowledgeConfiguration,
    YamlResponseConfiguration,
)
from cybertriage.adapters.knowledge.chunking import RecursiveKnowledgeChunker
from cybertriage.adapters.knowledge.retrieval import FederatedKnowledgeRetriever
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
    KnowledgeConfigurationProvider,
    ResponseConfigurationProvider,
)
from cybertriage.application.ports.knowledge import KnowledgeSource
from cybertriage.application.use_cases.analyze_alert import AnalyzeAlert
from cybertriage.application.use_cases.ingest_knowledge import IngestKnowledge
from cybertriage.application.use_cases.preview_response_action import PreviewResponseAction
from cybertriage.domain.configuration import KnowledgeSettings


DEFAULT_SOURCES_CONFIG = Path("config/sources.yaml")
DEFAULT_RESPONSE_CONFIG = Path("config/response_actions.yaml")


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


def build_analyze_alert(
    database_directory: Path,
    catalog_path: Path | None = None,
    model_name: str | None = None,
    sources_config_path: Path = DEFAULT_SOURCES_CONFIG,
    configuration: KnowledgeConfigurationProvider | None = None,
) -> AnalyzeAlert:
    settings = _load_knowledge(sources_config_path, configuration)
    if not database_directory.is_dir():
        raise FileNotFoundError(f"Knowledge database directory not found: {database_directory}")

    collections = [name for enabled, name, _ in _source_bindings(settings).values() if enabled]
    if not collections:
        raise ValueError("Enable at least one knowledge source in sources.yaml.")
    embeddings = RunbookEmbeddings()
    retriever = FederatedKnowledgeRetriever(tuple(
        ChromaKnowledgeIndex(
            directory=database_directory,
            embeddings=embeddings,
            collection_name=name,
            create_if_missing=False,
        )
        for name in collections
    ))
    model = OllamaTriageModel(ChatOllama(
        model=model_name or os.environ.get("CYBERTRIAGE_MODEL", "qwen3:4b-instruct"),
        base_url="http://localhost:11434",
        temperature=0,
        num_ctx=8192,
        num_predict=800,
        reasoning=False,
        client_kwargs={"timeout": 180.0},
    ))
    catalog = load_event_catalog(catalog_path) if catalog_path is not None else None
    return AnalyzeAlert(retriever=retriever, model=model, retrieval_limit=3, catalog=catalog)


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
