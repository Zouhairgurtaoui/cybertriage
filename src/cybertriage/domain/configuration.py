"""Typed configuration values, independent of YAML and concrete clients."""

from dataclasses import dataclass
from pathlib import Path


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

@dataclass(frozen=True)
class IndexerSettings:
    base_url: str
    username: str
    ca_bundle: Path