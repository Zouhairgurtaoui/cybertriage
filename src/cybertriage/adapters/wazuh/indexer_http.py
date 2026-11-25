import json
from pathlib import Path
from urllib.parse import urlsplit

import requests
from requests.auth import HTTPBasicAuth

from cybertriage.adapters.wazuh.authentication_query import (
    build_authentication_query,
)
from cybertriage.domain.investigation import (
    AuthenticationSearchRequest,
    InvestigationSearchError,
)


MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _unique_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys.")
        result[key] = value

    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Nonstandard JSON constant.")


def _validate_response(
    payload: object,
    request: AuthenticationSearchRequest,
) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object.")

    if payload.get("timed_out") is not False:
        raise ValueError("Search completion was not confirmed.")

    if payload.get("terminated_early", False) is not False:
        raise ValueError("Search terminated early.")

    shards = payload.get("_shards")

    if not isinstance(shards, dict):
        raise ValueError("Missing shard information.")

    counts = [
        shards.get("total"),
        shards.get("successful"),
        shards.get("failed"),
    ]

    if any(type(value) is not int or value < 0 for value in counts):
        raise ValueError("Invalid shard information.")

    total, successful, failed = counts

    if total == 0 or successful != total or failed != 0:
        raise ValueError("Search did not complete across all shards.")

    hits = payload.get("hits")

    if not isinstance(hits, dict):
        raise ValueError("Missing search results.")

    documents = hits.get("hits")

    if not isinstance(documents, list):
        raise ValueError("Invalid search results.")

    if len(documents) > request.limit + 1:
        raise ValueError("Search exceeded the requested result count.")

    return payload


class WazuhIndexerHttpClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        ca_bundle: Path,
    ):
        parsed = urlsplit(base_url)

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or any(character.isspace() for character in base_url)
        ):
            raise ValueError(
                "Expected an HTTPS Indexer origin without credentials, "
                "a path, query, or fragment."
            )

        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("Invalid Indexer port.")

        if (
            not isinstance(username, str)
            or not username.strip()
            or ":" in username
        ):
            raise ValueError("Invalid Indexer username.")

        if not isinstance(password, str) or not password:
            raise ValueError("An Indexer password is required.")

        # Requests' Basic authentication encodes credentials as Latin-1.
        try:
            username.encode("latin-1")
            password.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError(
                "Indexer credentials must be compatible with "
                "HTTP Basic authentication encoding."
            ) from None

        if not ca_bundle.is_file():
            raise ValueError("The trusted CA bundle was not found.")

        self._search_url = (
            f"{base_url.rstrip('/')}/wazuh-alerts-*/_search"
        )
        self._auth = HTTPBasicAuth(username, password)
        self._ca_bundle = str(ca_bundle.resolve())

    def search_authentication(
        self,
        request: AuthenticationSearchRequest,
    ) -> dict[str, object]:
        try:
            with requests.Session() as session:
                # Use the explicitly configured credentials, CA, and endpoint.
                session.trust_env = False
                session.auth = self._auth

                with session.post(
                    self._search_url,
                    params={
                        "allow_partial_search_results": "false",
                        "allow_no_indices": "false",
                        "ignore_unavailable": "false",
                    },
                    json=build_authentication_query(request),
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        "User-Agent": "CyberTriage/0.1",
                    },
                    verify=self._ca_bundle,
                    timeout=(5, 10),
                    stream=True,
                    allow_redirects=False,
                ) as response:
                    if response.status_code in {401, 403}:
                        raise InvestigationSearchError(
                            "Indexer authentication or authorization failed."
                        )

                    if response.status_code != 200:
                        raise InvestigationSearchError(
                            "Indexer search returned HTTP "
                            f"{response.status_code}."
                        )

                    media_type = response.headers.get(
                        "Content-Type", ""
                    ).split(";", 1)[0].strip().lower()

                    if media_type != "application/json":
                        raise ValueError("Expected a JSON response.")

                    encoding = response.headers.get(
                        "Content-Encoding", ""
                    ).strip().lower()

                    if encoding not in ("", "identity"):
                        raise ValueError(
                            "Unexpected compressed response."
                        )

                    declared_length = response.headers.get(
                        "Content-Length"
                    )

                    if declared_length is not None:
                        if (
                            not declared_length.isascii()
                            or not declared_length.isdecimal()
                            or int(declared_length) > MAX_RESPONSE_BYTES
                        ):
                            raise ValueError(
                                "Invalid or excessive response size."
                            )

                    body = bytearray()

                    for block in response.iter_content(
                        chunk_size=16 * 1024
                    ):
                        if len(body) + len(block) > MAX_RESPONSE_BYTES:
                            raise ValueError(
                                "Indexer response exceeded the size limit."
                            )

                        body.extend(block)

            payload = json.loads(
                body.decode("utf-8-sig"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )

            return _validate_response(payload, request)

        except requests.exceptions.SSLError:
            raise InvestigationSearchError(
                "Indexer TLS verification failed."
            ) from None

        except requests.exceptions.Timeout:
            raise InvestigationSearchError(
                "Indexer connection or response read timed out."
            ) from None

        except requests.RequestException:
            raise InvestigationSearchError(
                "Indexer request failed."
            ) from None

        except (OSError, ValueError, RecursionError):
            raise InvestigationSearchError(
                "Indexer returned an invalid or incomplete response, "
                "or its local connection files could not be read."
            ) from None