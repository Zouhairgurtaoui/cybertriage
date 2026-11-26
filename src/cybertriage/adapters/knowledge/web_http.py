"""Pinned public HTTPS with fixed routes, verified TLS and bounded responses."""

import http.client
import ipaddress
import socket
import ssl
from time import monotonic
from urllib.parse import urljoin, urlsplit

from cybertriage.application.policies.live_web import approved_url
from cybertriage.domain.live_web import (
    WebBudgetError, WebFetchError, WebPolicyError, WebRequestBudget, WebResponse, WebTransientError,
)

MAX_HTML_BYTES = 2 * 1024 * 1024


def resolve_public_addresses(host: str) -> tuple[str, ...]:
    try:
        results = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise WebTransientError("Public source DNS resolution failed.") from None
    addresses = set()
    for _, _, _, _, address in results:
        ip = ipaddress.ip_address(address[0])
        check = getattr(ip, "ipv4_mapped", None) or ip
        transition = getattr(ip, "sixtofour", None) is not None or getattr(ip, "teredo", None) is not None
        if not check.is_global or check.is_multicast or check.is_unspecified or check.is_reserved or transition:
            raise WebPolicyError("Documentation DNS includes a non-public destination.")
        addresses.add(str(ip))
    if not addresses or len(addresses) > 64:
        raise WebPolicyError("Invalid documentation DNS response.")
    return tuple(sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, value)))[:2]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port=443, timeout=timeout, context=context)
        self._address = address
        self._connect_timeout = timeout
        self._tls_context = context

    def connect(self) -> None:
        family = socket.AF_INET6 if ipaddress.ip_address(self._address).version == 6 else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw.settimeout(self._connect_timeout)
            raw.connect((self._address, 443))
            self.sock = self._tls_context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _validator(value: str | None) -> str | None:
    if value is not None and (len(value) > 1024 or not value.isascii() or not value.isprintable()):
        raise WebFetchError("Invalid public cache validator.")
    return value


class ApprovedPublicHttpFetcher:
    def __init__(self):
        self._tls = ssl.create_default_context()
        self._tls.minimum_version = ssl.TLSVersion.TLSv1_2

    def fetch(self, url: str, budget: WebRequestBudget, *, etag: str | None = None,
              last_modified: str | None = None) -> WebResponse:
        url = approved_url(url)
        etag, last_modified = _validator(etag), _validator(last_modified)
        original_host = urlsplit(url).hostname
        visited = set()
        for _ in range(3):
            if url in visited:
                raise WebPolicyError("Documentation redirect loop.")
            visited.add(url)
            if budget.remaining <= 0 or monotonic() >= budget.deadline:
                raise WebBudgetError("Live request budget exhausted.")
            parsed = urlsplit(url)
            host = parsed.hostname
            if host is None or host != original_host:
                raise WebPolicyError("Cross-host documentation redirect denied.")
            addresses = resolve_public_addresses(host)
            redirect = None
            last_error = None
            for address in addresses:
                timeout = budget.consume()
                connection = _PinnedHTTPSConnection(host, address, min(5.0, timeout), self._tls)
                try:
                    headers = {"User-Agent": "CyberTriage/0.1", "Accept": "text/html", "Accept-Encoding": "identity", "Connection": "close"}
                    if etag is not None:
                        headers["If-None-Match"] = _validator(etag) or ""
                    if last_modified is not None:
                        headers["If-Modified-Since"] = _validator(last_modified) or ""
                    connection.request("GET", parsed.path, headers=headers)
                    if connection.sock is not None:
                        connection.sock.settimeout(min(10.0, max(0.1, budget.deadline - monotonic())))
                    response = connection.getresponse()
                    for name in ("Content-Length", "Content-Type", "Content-Encoding", "Location", "ETag", "Last-Modified"):
                        if len(response.headers.get_all(name, [])) > 1:
                            raise WebFetchError("Ambiguous documentation response headers.")
                    if response.status in {301, 302, 303, 307, 308}:
                        location = response.getheader("Location")
                        if not location:
                            raise WebPolicyError("Documentation redirect has no destination.")
                        try:
                            redirect = approved_url(urljoin(url, location))
                        except ValueError:
                            raise WebPolicyError("Malformed documentation redirect.") from None
                        if urlsplit(redirect).hostname != original_host:
                            raise WebPolicyError("Cross-host documentation redirect denied.")
                        break
                    if response.status in {404, 410}:
                        return WebResponse(url, response.status)
                    if response.status == 304:
                        if etag is None and last_modified is None:
                            raise WebFetchError("Unexpected unvalidated 304 response.")
                        return WebResponse(url, 304, etag=_validator(response.getheader("ETag")),
                                           last_modified=_validator(response.getheader("Last-Modified")))
                    if response.status in {408, 429} or response.status >= 500:
                        raise WebTransientError("Public documentation is temporarily unavailable.")
                    if response.status != 200:
                        raise WebFetchError("Public documentation returned an unexpected HTTP status.")
                    media = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
                    encoding = (response.getheader("Content-Encoding") or "identity").strip().lower()
                    if media != "text/html" or encoding not in {"", "identity"}:
                        raise WebFetchError("Expected uncompressed HTML documentation.")
                    length = response.getheader("Content-Length")
                    if length is not None and (len(length) > 10 or not length.isascii() or not length.isdecimal() or int(length) > MAX_HTML_BYTES):
                        raise WebFetchError("Public documentation exceeds its body budget.")
                    if response.getheader("Transfer-Encoding") and length is not None:
                        raise WebFetchError("Ambiguous documentation body framing.")
                    body = bytearray()
                    while True:
                        if monotonic() >= budget.deadline:
                            raise WebBudgetError("Live request deadline exhausted.")
                        block = response.read1(16384)
                        if not block:
                            break
                        body.extend(block)
                        if len(body) > MAX_HTML_BYTES:
                            raise WebFetchError("Public documentation exceeds its body budget.")
                    if not body or length is not None and len(body) != int(length):
                        raise WebFetchError("Public documentation body is incomplete.")
                    return WebResponse(url, 200, bytes(body), _validator(response.getheader("ETag")),
                                       _validator(response.getheader("Last-Modified")))
                except ssl.SSLError:
                    raise WebFetchError("Public documentation TLS verification failed.") from None
                except (OSError, http.client.HTTPException) as error:
                    last_error = error
                finally:
                    connection.close()
            if redirect is not None:
                url = redirect
                # Validators are scoped to a resource, not an arbitrary redirect target.
                etag, last_modified = None, None
                continue
            if last_error is not None:
                raise WebTransientError("Public documentation connection/read failed.") from None
        raise WebPolicyError("Documentation redirect limit exceeded.")
