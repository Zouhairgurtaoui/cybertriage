"""Parse bounded YAML files into typed settings without framework dependencies in core code."""

import re
from ipaddress import ip_network
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from yaml.tokens import AliasToken, AnchorToken, TagToken

from cybertriage.domain.configuration import (
    KnowledgePage, KnowledgeSettings, MicrosoftSettings, MitreSettings,
)
from cybertriage.domain.response import ResponseActionRule, ResponseSettings


MAX_CONFIG_BYTES = 64 * 1024


class _UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("Configuration keys must be unique strings.")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _read_yaml(path: Path) -> dict:
    with path.open("rb") as file:
        raw = file.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError(f"Configuration exceeds its size limit: {path}")
    text = raw.decode("utf-8-sig")
    try:
        if any(isinstance(token, (AliasToken, AnchorToken, TagToken)) for token in yaml.scan(text)):
            raise ValueError("YAML aliases, anchors and explicit tags are not supported.")
        result = yaml.load(text, Loader=_UniqueSafeLoader)
    except (yaml.YAMLError, RecursionError) as error:
        raise ValueError(f"Invalid YAML configuration: {path}") from error
    if not isinstance(result, dict):
        raise ValueError(f"Configuration must contain a mapping: {path}")
    return result


def _fields(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} requires exactly these fields: {sorted(expected)}")
    return value


def _text(value: object, label: str, limit: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"Invalid {label}.")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"Control characters are not allowed in {label}.")
    return value.strip()


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be true or false.")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}.")
    return value


def _identifier(value: object, label: str) -> str:
    value = _text(value, label, 64)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value):
        raise ValueError(f"Invalid identifier for {label}.")
    return value


def _collection(value: object) -> str:
    value = _text(value, "collection name", 512)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,510}[A-Za-z0-9]", value):
        raise ValueError("Collection names must contain 3-512 permitted characters.")
    return value


def _learn_url(value: object) -> str:
    value = _text(value, "Microsoft Learn URL").rstrip("/")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.netloc != "learn.microsoft.com"
            or parsed.query or parsed.fragment):
        raise ValueError("Microsoft sources require an HTTPS learn.microsoft.com URL without query or fragment.")
    return value


def _identifiers(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a nonempty list.")
    result = tuple(_identifier(item, label) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"Duplicate entries in {label}.")
    return result


class YamlKnowledgeConfiguration:
    def __init__(self, path: Path):
        self._path = path

    def load(self) -> KnowledgeSettings:
        root = _fields(_read_yaml(self._path),
                       {"schema_version", "chunking", "event_catalog_url", "sources"}, "sources config")
        _integer(root["schema_version"], "schema_version", 1, 1)
        chunking = _fields(root["chunking"], {"size", "overlap"}, "chunking")
        size = _integer(chunking["size"], "chunk size", 200, 3000)
        overlap = _integer(chunking["overlap"], "chunk overlap", 0, size - 1)
        sources = _fields(root["sources"], {"mitre", "microsoft"}, "sources")
        mitre = _fields(sources["mitre"], {"enabled", "revision", "collection"}, "MITRE source")
        revision = _text(mitre["revision"], "MITRE revision", 40)
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("MITRE revision must be a full lowercase Git commit SHA.")
        microsoft = _fields(sources["microsoft"],
                            {"enabled", "collection", "base_url", "pages"}, "Microsoft source")
        if not isinstance(microsoft["pages"], list) or not 1 <= len(microsoft["pages"]) <= 100:
            raise ValueError("Microsoft pages must contain 1-100 entries.")
        pages = []
        for entry in microsoft["pages"]:
            entry = _fields(entry, {"slug", "expected_heading"}, "Microsoft page")
            slug = _text(entry["slug"], "page slug", 120)
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
                raise ValueError("Page slugs must be lowercase names without path separators.")
            pages.append(KnowledgePage(slug, _text(entry["expected_heading"], "expected heading", 200)))
        if len({page.slug for page in pages}) != len(pages):
            raise ValueError("Duplicate Microsoft page slugs.")
        mitre_settings = MitreSettings(
            _boolean(mitre["enabled"], "MITRE enabled"), revision, _collection(mitre["collection"]),
        )
        microsoft_settings = MicrosoftSettings(
            _boolean(microsoft["enabled"], "Microsoft enabled"), _collection(microsoft["collection"]),
            _learn_url(microsoft["base_url"]), tuple(pages),
        )
        if mitre_settings.collection_name == microsoft_settings.collection_name:
            raise ValueError("Knowledge sources must use distinct collections.")
        return KnowledgeSettings(mitre_settings, microsoft_settings,
                                 _learn_url(root["event_catalog_url"]), size, overlap)


class YamlResponseConfiguration:
    def __init__(self, path: Path):
        self._path = path

    def load(self) -> ResponseSettings:
        root = _fields(_read_yaml(self._path),
                       {"schema_version", "execution_enabled", "approval_ttl_seconds", "actions"},
                       "response config")
        _integer(root["schema_version"], "schema_version", 1, 1)
        actions = root["actions"]
        if not isinstance(actions, dict) or not 1 <= len(actions) <= 50:
            raise ValueError("Response actions must contain 1-50 rules.")
        rules = []
        for action, values in actions.items():
            action = _identifier(action, "action name")
            values = _fields(values, {
                "enabled", "requires_compromise_confirmation", "requires_analyst_approval",
                "allowed_targets", "required_parameters", "max_duration_seconds", "protected_networks",
            }, "response action")
            networks = values["protected_networks"]
            if not isinstance(networks, list) or len(networks) > 100:
                raise ValueError("protected_networks must be a list of at most 100 CIDRs.")
            protected = tuple(str(ip_network(_text(item, "protected network", 64))) for item in networks)
            rules.append(ResponseActionRule(
                action=action,
                enabled=_boolean(values["enabled"], "action enabled"),
                requires_compromise_confirmation=_boolean(values["requires_compromise_confirmation"], "confirmation requirement"),
                requires_analyst_approval=_boolean(values["requires_analyst_approval"], "approval requirement"),
                allowed_targets=_identifiers(values["allowed_targets"], "allowed targets"),
                required_parameters=_identifiers(values["required_parameters"], "required parameters"),
                max_duration_seconds=_integer(values["max_duration_seconds"], "maximum duration", 1, 86400),
                protected_networks=protected,
            ))
        return ResponseSettings(
            _boolean(root["execution_enabled"], "execution enabled"),
            _integer(root["approval_ttl_seconds"], "approval lifetime", 1, 86400),
            tuple(rules),
        )
