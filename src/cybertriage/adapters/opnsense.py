"""Verified HTTPS adapter for one dedicated external OPNsense alias."""

import json
import os
import re
import time
from ipaddress import ip_address, ip_network
from urllib.parse import quote

import requests

from cybertriage.domain.firewall import FirewallTarget
from cybertriage.domain.response_workflow import ResponseError


class OpnsenseFirewallGateway:
    def __init__(self, target: FirewallTarget):
        self._target = target

    def _request(self, method: str, path: str, payload=None, parameters=None):
        key, secret = os.environ.get(self._target.api_key_env), os.environ.get(self._target.api_secret_env)
        if not key or not secret or len(key) > 1024 or len(secret) > 1024 or any(ord(char) < 32 for char in key + secret):
            raise ResponseError("Configured firewall API credentials are unavailable or invalid.")
        try:
            with requests.Session() as session:
                session.trust_env = False
                started = time.monotonic()
                with session.request(method, self._target.base_url + path, json=payload, params=parameters,
                    auth=(key, secret), verify=True if self._target.ca_bundle == "system" else self._target.ca_bundle,
                    headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                    timeout=(5, 10), allow_redirects=False, stream=True) as response:
                    if response.status_code != 200 or response.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/json":
                        raise ResponseError("Firewall rejected the request or returned an unexpected response.")
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise ResponseError("Compressed firewall responses are not accepted.")
                    body = bytearray()
                    for chunk in response.iter_content(8192):
                        if len(body) + len(chunk) > 262144 or time.monotonic() - started > 20:
                            raise ResponseError("Firewall response exceeded its size/time budget.")
                        body.extend(chunk)
            def unique(pairs):
                values = {}
                for name, value in pairs:
                    if name in values:
                        raise ValueError("Duplicate key")
                    values[name] = value
                return values
            data = json.loads(body.decode("utf-8"), object_pairs_hook=unique,
                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonstandard JSON")))
            if not isinstance(data, dict):
                raise ResponseError("Firewall response must be an object.")
            return data
        except ResponseError:
            raise
        except (requests.RequestException, ValueError, UnicodeError, RecursionError) as error:
            raise ResponseError("Firewall connection or response validation failed.") from error

    def validate_container(self) -> None:
        alias = quote(self._target.alias, safe="")
        identity = self._request("GET", "/api/firewall/alias/get_alias_u_u_i_d/" + alias)
        value = identity.get("uuid")
        if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9-]{36}", value):
            raise ResponseError("The dedicated OPNsense alias was not found.")
        data = self._request("GET", "/api/firewall/alias/get_item/" + value).get("alias")
        if not isinstance(data, dict) or data.get("name") != self._target.alias or str(data.get("enabled")) != "1":
            raise ResponseError("The dedicated OPNsense alias is unavailable or disabled.")
        kind = data.get("type")
        selected = isinstance(kind, dict) and isinstance(kind.get("external"), dict) and str(kind["external"].get("selected")) == "1"
        if kind != "external" and not selected:
            raise ResponseError("Only a dedicated external alias can be managed.")

    def contains(self, address: str) -> bool:
        address = str(ip_address(address))
        data = self._request("GET", "/api/firewall/alias_util/list/" + quote(self._target.alias, safe=""),
                             parameters={"searchPhrase": address, "current": 1, "rowCount": 100})
        rows, total = data.get("rows"), data.get("total")
        if not isinstance(rows, list) or type(total) is not int or total != len(rows) or len(rows) > 100:
            raise ResponseError("Firewall alias lookup is incomplete; presence cannot be established.")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("ip"), str):
                raise ResponseError("Firewall alias lookup contains invalid entries.")
            entry = ip_network(row["ip"], strict=False)
            if ip_address(address) in entry:
                return True
        return False

    def _change(self, operation: str, address: str) -> None:
        data = self._request("POST", f"/api/firewall/alias_util/{operation}/" + quote(self._target.alias, safe=""),
                             payload={"address": str(ip_address(address))})
        if data.get("status") != "done":
            raise ResponseError("Firewall did not acknowledge the alias change.")

    def add(self, address: str) -> None:
        self._change("add", address)

    def remove(self, address: str) -> None:
        self._change("delete", address)
