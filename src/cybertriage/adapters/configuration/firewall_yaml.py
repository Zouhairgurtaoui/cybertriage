"""Strict named-target configuration; firewall secrets remain in the environment."""

import re
from pathlib import Path
from urllib.parse import urlsplit

from cybertriage.adapters.configuration.yaml_files import _fields, _read_yaml
from cybertriage.domain.firewall import FirewallTarget
from cybertriage.domain.response_workflow import ResponseError


class YamlFirewallConfiguration:
    def __init__(self, path: Path, registered_drivers: tuple[str, ...] = ("opnsense",)):
        self._path = path
        self._drivers = frozenset(registered_drivers)

    def load(self) -> tuple[FirewallTarget, ...]:
        root = _fields(_read_yaml(self._path), {"schema_version", "targets"}, "firewall configuration")
        if type(root["schema_version"]) is not int or root["schema_version"] != 1 or not isinstance(root["targets"], dict) or len(root["targets"]) > 20:
            raise ResponseError("Firewall configuration requires schema version 1 and at most 20 targets.")
        targets = []
        for name, values in root["targets"].items():
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", name):
                raise ResponseError("Invalid firewall target name.")
            row = _fields(values, {"driver", "base_url", "alias", "ca_bundle", "api_key_env", "api_secret_env",
                                   "exclusive_alias", "application_managed_expiry"}, "firewall target")
            if row["driver"] not in self._drivers:
                raise ResponseError("No installed adapter for this firewall driver; configure a registered provider.")
            for field in ("base_url", "alias", "ca_bundle", "api_key_env", "api_secret_env"):
                value = row[field]
                if not isinstance(value, str) or not value or value != value.strip() or not value.isprintable() or len(value) > 2048:
                    raise ResponseError(f"Invalid firewall {field}.")
            parsed = urlsplit(row["base_url"])
            try:
                port = parsed.port
            except ValueError as error:
                raise ResponseError("Invalid firewall port.") from error
            if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or (port is not None and not 1 <= port <= 65535):
                raise ResponseError("Firewall URL must be a verified HTTPS origin without credentials or paths.")
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", row["alias"]):
                raise ResponseError("Invalid dedicated firewall alias name.")
            for field in ("api_key_env", "api_secret_env"):
                if not re.fullmatch(r"CYBERTRIAGE_[A-Z0-9_]{1,100}", row[field]):
                    raise ResponseError("Firewall credential references must name CYBERTRIAGE_ environment variables.")
            if row["api_key_env"] == row["api_secret_env"] or row["exclusive_alias"] is not True or row["application_managed_expiry"] is not True:
                raise ResponseError("Use distinct credentials, an exclusive alias and explicit application-managed expiry.")
            if row["ca_bundle"] != "system":
                path = Path(row["ca_bundle"]).expanduser()
                if not path.is_absolute() or not path.is_file():
                    raise ResponseError("Firewall CA bundle must be an existing absolute file path or system.")
                row["ca_bundle"] = str(path.resolve())
            targets.append(FirewallTarget(name, row["driver"], row["base_url"].rstrip("/"), row["alias"],
                row["ca_bundle"], row["api_key_env"], row["api_secret_env"], True))
        return tuple(sorted(targets, key=lambda target: target.name))
