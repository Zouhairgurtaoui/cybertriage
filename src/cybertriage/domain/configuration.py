"""Typed configuration values, independent of YAML and concrete clients."""

from dataclasses import dataclass, field
from pathlib import Path
from cybertriage.domain.live_web import LiveWebSettings


@dataclass(frozen=True)
class KnowledgePage:
    slug: str
    expected_heading: str


@dataclass(frozen=True)
class MitreSettings:
    enabled: bool
    revision: str
    collection_name: str


@dataclass(frozen=True)
class MicrosoftSettings:
    enabled: bool
    collection_name: str
    base_url: str
    pages: tuple[KnowledgePage, ...]


@dataclass(frozen=True)
class KnowledgeSettings:
    mitre: MitreSettings
    microsoft: MicrosoftSettings
    catalog_url: str
    chunk_size: int
    chunk_overlap: int
    live_web: LiveWebSettings = field(default_factory=LiveWebSettings)

@dataclass(frozen=True)
class IndexerSettings:
    base_url: str
    username: str
    ca_bundle: Path
