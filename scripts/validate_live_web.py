"""Offline public-web boundaries: fake HTTP/DNS, isolated cache databases, no LLMs."""

import json
import socket
import ssl
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from time import monotonic, perf_counter
import traceback
from unittest.mock import patch
from uuid import uuid4

import yaml

from cybertriage.adapters.configuration.yaml_files import YamlKnowledgeConfiguration
from cybertriage.adapters.knowledge.chunking import RecursiveKnowledgeChunker
from cybertriage.adapters.knowledge.web_http import ApprovedPublicHttpFetcher, _PinnedHTTPSConnection, resolve_public_addresses
from cybertriage.adapters.knowledge.web_parsing import OfficialDocumentationParser
from cybertriage.adapters.models.reference_formatting import format_reference
from cybertriage.adapters.storage.web_cache_sqlite import SqlitePublicDocumentCache
from cybertriage.application.policies.live_web import approved_url, plan_web_targets
from cybertriage.application.services.live_knowledge import LiveDocumentReader, LiveWebKnowledgeRetriever
from cybertriage.domain.live_web import (
    LiveWebSettings, WebBudgetError, WebCacheEntry, WebCacheError, WebFetchError,
    WebPolicyError, WebRequestBudget, WebResponse, WebTransientError,
)
from cybertriage.domain.retrieval import KnowledgeRetrievalError, RetrievalContext, RetrievalOutcome
from cybertriage.domain.security_event import EventIdentity
from cybertriage.domain.triage import RetrievedReference

ROOT = Path.cwd() / "data" / "validation" / f"live-web-{uuid4().hex}"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
CONTEXT = RetrievalContext(EventIdentity("Microsoft-Windows-Security-Auditing", "Security", 4725), "An account was disabled.")
SETTINGS = LiveWebSettings(enabled=True, ttl_seconds=300, not_found_ttl_seconds=60, max_stale_seconds=600)
PARSER = OfficialDocumentationParser()
CHECKS = []


def check(name):
    def register(function):
        CHECKS.append((name, function))
        return function
    return register


def expect(error_type, operation):
    try:
        operation()
    except error_type:
        return
    raise AssertionError(f"Expected {error_type.__name__}")


def budget(count=6):
    return WebRequestBudget(count, monotonic() + 100)


def microsoft(identifier="4725"):
    return (f'<main><h1>{identifier}(S): Account event.</h1><div class="content"><p>Event Description: '
            f'{identifier}(S) documents an account event. ' + "Public investigation guidance. " * 10 + '</p><script>UNTRUSTED_SCRIPT</script></div></main>').encode()


def mitre(identifier="T1098.007", platforms="Windows, Linux"):
    return (f'<h1>Account guidance</h1><div class="card-data">ID: {identifier}</div><div class="card-data">Platforms: {platforms}</div>'
            '<div class="description-body"><p>' + "Account manipulation guidance for analyst review. " * 10 + '</p></div><script>UNTRUSTED_SCRIPT</script>').encode()


def target(source="microsoft", identifier=None):
    if source == "microsoft":
        return plan_web_targets("", CONTEXT, (), SETTINGS)[0]
    return plan_web_targets(identifier or "T1098.007", RetrievalContext(), (), replace(SETTINGS, sources=("mitre",)))[0]


class Clock:
    def __init__(self):
        self.now = BASE
    def __call__(self):
        return self.now


class Fetcher:
    def __init__(self, actions):
        self.actions = list(actions)
        self.calls = []
    def fetch(self, url, budget, *, etag=None, last_modified=None):
        budget.consume()
        self.calls.append({"url": url, "etag": etag, "last_modified": last_modified})
        if not self.actions:
            raise AssertionError("Unexpected additional HTTP request")
        action = self.actions.pop(0)
        if isinstance(action, Exception):
            raise action
        status, body = action
        return WebResponse(url, status, body, '"fixture-etag"' if status == 200 else None)


def fixture(name, actions, settings=SETTINGS):
    cache = SqlitePublicDocumentCache(ROOT / f"{name}.sqlite3")
    fetcher, clock = Fetcher(actions), Clock()
    return cache, fetcher, clock, LiveDocumentReader(cache, fetcher, PARSER, settings, clock)


class Local:
    def __init__(self, references=(), failure=False):
        self.references, self.failure = tuple(references), failure
    def retrieve(self, query, k=3):
        return list(self.retrieve_for(query, RetrievalContext(), k).references)
    def retrieve_for(self, query, context, k=3):
        if self.failure:
            raise KnowledgeRetrievalError("Synthetic local failure")
        return RetrievalOutcome(self.references[:k], '{"version":1,"policy":"fixture"}')


@check("Only public identifiers become vendor routes; private query text is not submitted")
def privacy():
    secret = "alice@corp.local 10.0.2.5 PRIVATE_MARKER"
    result = plan_web_targets(secret + " T1098.007", CONTEXT, (), SETTINGS)
    assert len(result) == 2
    serialized = json.dumps([item.urls for item in result])
    assert all(value not in serialized for value in secret.split())
    sysmon = RetrievalContext(EventIdentity("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", 4725))
    assert plan_web_targets("", sysmon, (), SETTINGS) == ()
    assert plan_web_targets("no identifier", RetrievalContext(), (), SETTINGS) == ()


@check("URLs reject private hosts, credentials, ports, queries, fragments and encoded/traversal paths")
def urls():
    for value in ("http://attack.mitre.org/techniques/T1098/", "https://127.0.0.1/", "https://attack.mitre.org.evil.test/techniques/T1098/",
                  "https://user@attack.mitre.org/techniques/T1098/", "https://attack.mitre.org:444/techniques/T1098/",
                  "https://attack.mitre.org/techniques/T1098/?secret=x", "https://attack.mitre.org/techniques/T1098/#x",
                  "https://attack.mitre.org/techniques/%2e%2e/", "https://attack.mitre.org/techniques/../T1098/", "https://learn.microsoft.com/en-us/answers/", "https://[/"):
        expect(WebPolicyError, lambda: approved_url(value))


@check("DNS rejects private, loopback, link-local, shared, mapped-private and mixed answers")
def dns():
    for value in ("127.0.0.1", "10.0.2.1", "169.254.169.254", "100.64.0.1", "::1", "::ffff:127.0.0.1", "192.0.2.1", "2002:7f00:1::"):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (value, 443))]
        with patch("cybertriage.adapters.knowledge.web_http.socket.getaddrinfo", return_value=answers):
            expect(WebPolicyError, lambda: resolve_public_addresses("learn.microsoft.com"))
    mixed = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ("8.8.8.8", "10.0.2.1")]
    with patch("cybertriage.adapters.knowledge.web_http.socket.getaddrinfo", return_value=mixed):
        expect(WebPolicyError, lambda: resolve_public_addresses("learn.microsoft.com"))


@check("Pinned TLS connects to the validated IP while preserving the approved hostname for certificate/SNI")
def pinned_tls():
    connected, names = [], []
    class Sock:
        def settimeout(self, value): pass
        def connect(self, value): connected.append(value)
        def close(self): pass
    class TLS:
        def wrap_socket(self, raw, server_hostname):
            names.append(server_hostname)
            return raw
    connection = _PinnedHTTPSConnection("learn.microsoft.com", "8.8.8.8", 5.0, ssl.create_default_context())
    setattr(connection, "_tls_context", TLS())
    with patch("cybertriage.adapters.knowledge.web_http.socket.socket", return_value=Sock()):
        connection.connect()
    assert connected == [("8.8.8.8", 443)] and names == ["learn.microsoft.com"]
    connection.close()


class Response:
    def __init__(self, status, body=b"", headers=None):
        self.status, self.body, self.offset = status, body, 0
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value
    def getheader(self, key):
        return self.headers.get(key)
    def read1(self, size):
        value = self.body[self.offset:self.offset + size]
        self.offset += len(value)
        return value


def http_fixture(responses):
    calls = []
    class Connection:
        sock = None
        def __init__(self, host, address, timeout, context):
            self.response = responses.pop(0)
        def request(self, method, path, headers):
            calls.append((method, path, headers))
        def getresponse(self):
            return self.response
        def close(self): pass
    return Connection, calls


@check("HTTP sends bounded GET requests without cookies/authentication and rejects cross-host/private redirects")
def http_boundaries():
    approved = target().urls[0]
    for destination in ("https://127.0.0.1/", "https://attack.mitre.org/techniques/T1098/"):
        connection, calls = http_fixture([Response(302, headers={"Location": destination})])
        with patch("cybertriage.adapters.knowledge.web_http.resolve_public_addresses", return_value=("8.8.8.8",)), patch("cybertriage.adapters.knowledge.web_http._PinnedHTTPSConnection", connection):
            expect(WebPolicyError, lambda: ApprovedPublicHttpFetcher().fetch(approved, budget()))
        assert len(calls) == 1 and calls[0][0] == "GET"
        assert not {"Authorization", "Cookie", "Proxy-Authorization"} & calls[0][2].keys()


@check("HTTP rejects compressed, non-HTML, oversized and incomplete bodies")
def http_bodies():
    variants = [Response(200, b"x", {"Content-Type": "application/json"}),
                Response(200, b"x", {"Content-Type": "text/html", "Content-Encoding": "gzip"}),
                Response(200, b"x", {"Content-Type": "text/html", "Content-Length": str(3 * 1024 * 1024)}),
                Response(200, b"x", {"Content-Type": "text/html", "Content-Length": "20"})]
    for response in variants:
        connection, _ = http_fixture([response])
        with patch("cybertriage.adapters.knowledge.web_http.resolve_public_addresses", return_value=("8.8.8.8",)), patch("cybertriage.adapters.knowledge.web_http._PinnedHTTPSConnection", connection):
            expect(WebFetchError, lambda: ApprovedPublicHttpFetcher().fetch(target().urls[0], budget()))


@check("Budgets and invalid validators stop before DNS or connection attempts")
def request_limits():
    with patch("cybertriage.adapters.knowledge.web_http.resolve_public_addresses", side_effect=AssertionError("Unexpected DNS")):
        expect(WebBudgetError, lambda: ApprovedPublicHttpFetcher().fetch(target().urls[0], budget(0)))
        expect(WebFetchError, lambda: ApprovedPublicHttpFetcher().fetch(target().urls[0], budget(), etag="bad\r\nheader"))


@check("Official article parsers confirm identity/platforms and strip scripts; unrelated/challenge HTML fails")
def parsing():
    ms = target()
    document = PARSER.parse(ms, WebResponse(ms.urls[0], 200, microsoft()), BASE)
    assert document.platforms == ("Windows",) and "UNTRUSTED_SCRIPT" not in document.text
    attack = target("mitre")
    document = PARSER.parse(attack, WebResponse(attack.urls[0], 200, mitre()), BASE)
    assert document.platforms == ("Windows", "Linux")
    expect(WebFetchError, lambda: PARSER.parse(ms, WebResponse(ms.urls[0], 200, microsoft("4624")), BASE))
    expect(WebFetchError, lambda: PARSER.parse(attack, WebResponse(attack.urls[0], 200, mitre("T1098.003")), BASE))
    challenge = ('<main><h1>4725(S): Account event</h1><div class="content"><p>' + "Please sign in. " * 20 + '</p></div></main>').encode()
    expect(WebFetchError, lambda: PARSER.parse(ms, WebResponse(ms.urls[0], 200, challenge), BASE))


@check("Semantic article layouts and alternate approved routes work without accepting login-wall content")
def alternate_layouts():
    item = target("mitre")
    body = ('<main><h1>Technique guidance</h1><div>ID:<span>T1098.007</span></div><table><tr><th>Platforms:</th><td>Windows, Linux</td></tr></table><p>'
            + "Public account investigation guidance. " * 10 + '</p><h2>Examples</h2></main>').encode()
    document = PARSER.parse(item, WebResponse(item.urls[0], 200, body), BASE)
    assert document.platforms == ("Windows", "Linux")
    ms_body = microsoft().replace(b'<div class="content">', b'<article>').replace(b'</div></main>', b'</article></main>')
    assert PARSER.parse(target(), WebResponse(target().urls[0], 200, ms_body), BASE).platforms == ("Windows",)
    challenge = ('<main><h1>4725(S): Account event</h1><div class="content"><p>' + "Please sign in. " * 20 + '</p></div></main>').encode()
    _, fetcher, _, reader = fixture("alternate-route", [(200, challenge), (200, microsoft())])
    result = reader.read(target(), budget())
    assert result.status == "network" and "article_parse_failed" in result.diagnostic_codes and len(fetcher.calls) == 2


@check("Fresh positive cache avoids HTTP and retains stable public content provenance")
def fresh_cache():
    _, fetcher, _, reader = fixture("fresh", [(200, microsoft())])
    first, second = reader.read(target(), budget()), reader.read(target(), budget())
    assert first.status == "network" and second.status == "fresh_cache" and len(fetcher.calls) == 1
    assert first.entry.document.content_hash == second.entry.document.content_hash


@check("Expired cache revalidates with ETag without changing the original fetch time")
def conditional_cache():
    _, fetcher, clock, reader = fixture("conditional", [(200, microsoft()), (304, b"")])
    first = reader.read(target(), budget())
    clock.now += timedelta(seconds=301)
    second = reader.read(target(), budget())
    assert second.status == "revalidated" and second.entry.fetched_at == first.entry.fetched_at
    assert second.entry.validated_at == clock.now and fetcher.calls[-1]["etag"] == '"fixture-etag"'
    assert reader.read(target(), budget()).status == "fresh_cache" and len(fetcher.calls) == 2


@check("Missing pages try approved fallbacks and cache only a scoped negative result")
def not_found_cache():
    _, fetcher, _, reader = fixture("negative", [(404, b""), (404, b""), (404, b"")])
    first = reader.read(target(), budget())
    second = reader.read(target(), budget())
    assert first.status == second.status == "not_found" and first.entry.document is None
    assert first.http_requests == 3 and second.http_requests == 0 and len(fetcher.calls) == 3
    _, _, _, other = fixture("fallback", [(404, b""), (404, b""), (200, ('<main><h1>Audit catalogue</h1><div class="content"><table><tr><td>4725</td><td>' + "Account disable guidance. " * 10 + '</td></tr></table></div></main>').encode())])
    assert other.read(target(), budget()).status == "network"


@check("Only bounded stale cache is used for transient failures; policy errors never become stale success")
def stale_policy():
    _, _, clock, reader = fixture("stale", [(200, microsoft()), WebTransientError("fixture"), WebTransientError("fixture")])
    reader.read(target(), budget())
    clock.now += timedelta(seconds=301)
    assert reader.read(target(), budget()).status == "stale_cache"
    clock.now = BASE + timedelta(seconds=901)
    result = reader.read(target(), budget())
    assert result.status == "error" and result.entry is None
    _, _, clock, reader = fixture("denied", [(200, microsoft()), WebPolicyError("fixture")])
    reader.read(target(), budget()); clock.now += timedelta(seconds=301)
    assert reader.read(target(), budget()).entry is None


@check("Transient failures retain a short refresh lease to prevent repeated upstream requests")
def transient_backoff():
    _, fetcher, _, reader = fixture("backoff", [WebTransientError("fixture")])
    assert reader.read(target(), budget()).status == "error"
    assert reader.read(target(), budget()).status == "refresh_in_progress"
    assert len(fetcher.calls) == 1


@check("Public cache corruption and foreign-database paths fail without overwriting unrelated tables")
def cache_integrity():
    cache, fetcher, _, reader = fixture("corrupt", [(200, microsoft())])
    reader.read(target(), budget())
    with closing(sqlite3.connect(ROOT / "corrupt.sqlite3")) as connection:
        with connection:
            connection.execute("UPDATE public_web_documents SET payload_json=payload_json || ' '")
    expect(WebCacheError, lambda: cache.get(target().key))
    assert reader.read(target(), budget()).status == "error" and len(fetcher.calls) == 1
    path = ROOT / "foreign.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE alerts(value TEXT)")
    expect(WebCacheError, lambda: SqlitePublicDocumentCache(path).get("key"))
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("alerts",)]


@check("Concurrent refresh claims have one owner, and expired owners cannot overwrite or release a new lease")
def lease_ownership():
    cache = SqlitePublicDocumentCache(ROOT / "leases.sqlite3")
    item = target()
    with ThreadPoolExecutor(max_workers=4) as pool:
        tokens = list(pool.map(lambda _: cache.claim(item.key, BASE), range(4)))
    assert sum(token is not None for token in tokens) == 1
    old = next(token for token in tokens if token is not None)
    now = BASE + timedelta(seconds=61)
    new = cache.claim(item.key, now)
    assert new and new != old
    document = PARSER.parse(item, WebResponse(item.urls[0], 200, microsoft()), BASE)
    entry = WebCacheEntry(item.key, item.urls[0], document, BASE, BASE, BASE + timedelta(seconds=300))
    expect(WebCacheError, lambda: cache.save(entry, old, now))
    cache.release(item.key, old)
    assert cache.claim(item.key, now) is None
    cache.save(entry, new, now)
    assert cache.get(item.key).document.content_hash == document.content_hash


@check("Cache quota eviction is bounded and a failed oversized publication rolls all eviction writes back")
def cache_quotas():
    cache = SqlitePublicDocumentCache(ROOT / "quotas.sqlite3")
    items = []
    with patch("cybertriage.adapters.storage.web_cache_sqlite.MAX_CACHE_ENTRIES", 2):
        for index, identifier in enumerate((4720, 4722, 4725)):
            context = RetrievalContext(EventIdentity("Microsoft-Windows-Security-Auditing", "Security", identifier))
            item = plan_web_targets("", context, (), SETTINGS)[0]
            now = BASE + timedelta(seconds=index)
            document = PARSER.parse(item, WebResponse(item.urls[0], 200, microsoft(str(identifier))), now)
            token = cache.claim(item.key, now)
            assert token is not None
            entry = WebCacheEntry(item.key, item.urls[0], document, now, now, now + timedelta(seconds=300))
            cache.save(entry, token, now); cache.release(item.key, token)
            items.append((item, entry))
    assert cache.get(items[0][0].key) is None
    assert cache.get(items[1][0].key) is not None and cache.get(items[2][0].key) is not None
    item, entry = items[-1]
    token = cache.claim(item.key, BASE + timedelta(seconds=3))
    assert token is not None
    with patch("cybertriage.adapters.storage.web_cache_sqlite.MAX_CACHE_PAYLOAD_BYTES", 1):
        expect(WebCacheError, lambda: cache.save(entry, token, BASE + timedelta(seconds=3)))
    cache.release(item.key, token)
    assert cache.get(items[1][0].key) is not None and cache.get(items[2][0].key) is not None


@check("A held refresh lease returns labelled stale context or an explicit in-progress state without HTTP")
def held_lease():
    cache, fetcher, clock, reader = fixture("held", [(200, microsoft())])
    reader.read(target(), budget()); clock.now += timedelta(seconds=301)
    token = cache.claim(target().key, clock.now)
    assert token is not None
    result = reader.read(target(), budget())
    assert result.status == "stale_refresh_in_progress" and len(fetcher.calls) == 1
    cache.release(target().key, token)


@check("Combined retrieval labels live references, preserves local context on failures, and exposes lookup errors")
def augmentation():
    local = RetrievedReference("local", "Local guidance", "https://example.org/guidance", "Stored context.")
    _, _, _, reader = fixture("merge", [(200, microsoft())])
    retriever = LiveWebKnowledgeRetriever(Local([local]), reader, RecursiveKnowledgeChunker(), SETTINGS)
    result = retriever.retrieve_for("disabled account", CONTEXT, 3)
    assert result.references[0].provenance_json and local in result.references
    assert json.loads(result.references[0].provenance_json)["stale"] is False
    assert "Reference freshness" in format_reference(result.references[0], 1)
    trace = json.loads(result.trace_json)
    assert trace["web"]["http_requests"] == 1 and trace["web"]["lookups"][0]["status"] == "network"
    _, _, _, failed = fixture("failure", [WebTransientError("fixture")])
    result = LiveWebKnowledgeRetriever(Local([local]), failed, RecursiveKnowledgeChunker(), SETTINGS).retrieve_for("disabled account", CONTEXT, 3)
    assert result.references == (local,) and json.loads(result.trace_json)["web"]["lookups"][0]["status"] == "error"


@check("Disabled/no-target retrieval never fetches, and local source failures remain fatal")
def disabled_and_local_errors():
    _, fetcher, _, reader = fixture("disabled", [])
    retriever = LiveWebKnowledgeRetriever(Local(), reader, RecursiveKnowledgeChunker(), replace(SETTINGS, enabled=False))
    assert retriever.retrieve_for("T1098.007", CONTEXT, 3).references == () and fetcher.calls == []
    result = LiveWebKnowledgeRetriever(Local(), reader, RecursiveKnowledgeChunker(), SETTINGS).retrieve_for("generic query", RetrievalContext(), 3)
    assert json.loads(result.trace_json)["web"]["target_count"] == 0 and fetcher.calls == []
    expect(KnowledgeRetrievalError, lambda: LiveWebKnowledgeRetriever(Local(failure=True), reader, RecursiveKnowledgeChunker(), SETTINGS).retrieve_for("T1098.007", CONTEXT, 3))


@check("Fresh incompatible platform metadata removes an obsolete local candidate without inventing an attack finding")
def live_platforms():
    local = RetrievedReference("old", "T1547.015: Login Items", "https://attack.mitre.org/techniques/T1547/015/", "Legacy platform-unknown guidance.")
    settings = replace(SETTINGS, sources=("mitre",))
    _, _, _, reader = fixture("platform", [(200, mitre("T1547.015", "macOS"))], settings)
    result = LiveWebKnowledgeRetriever(Local([local]), reader, RecursiveKnowledgeChunker(), settings).retrieve_for("authentication", CONTEXT, 3)
    assert result.references == ()
    assert json.loads(result.trace_json)["web"]["local_platform_exclusions"] == 1


@check("Live YAML rejects unknown fields, null sections, unsafe paths, invalid bounds and unsupported sources")
def configuration():
    base = yaml.safe_load(Path("config/sources.yaml").read_text(encoding="utf-8"))
    variants = []
    for key, value in (("unknown", True), ("max_targets", True), ("max_http_requests", 100), ("ttl_seconds", 0), ("sources", ["arbitrary"]),
                       ("cache_path", "../secret.sqlite3"), ("cache_path", "C:/secret.sqlite3")):
        item = json.loads(json.dumps(base)); item["live_web"][key] = value; variants.append(item)
    item = json.loads(json.dumps(base)); item["live_web"] = None; variants.append(item)
    for number, item in enumerate(variants):
        path = ROOT / f"invalid-{number}.yaml"
        path.write_text(yaml.safe_dump(item), encoding="utf-8")
        expect(ValueError, lambda: YamlKnowledgeConfiguration(path).load())
    base.pop("live_web")
    path = ROOT / "legacy.yaml"; path.write_text(yaml.safe_dump(base), encoding="utf-8")
    assert YamlKnowledgeConfiguration(path).load().live_web.enabled is False


def main():
    if not __debug__ or not Path("pyproject.toml").is_file():
        raise SystemExit("Run from the project root without -O.")
    ROOT.mkdir(parents=True, exist_ok=False)
    print("Isolated validation directory:", ROOT, flush=True)
    results = []
    for name, function in CHECKS:
        started = perf_counter()
        try:
            function()
        except Exception as error:
            results.append({"name": name, "status": "failed", "error_type": type(error).__name__, "details": str(error), "traceback": traceback.format_exc()})
            print(f"FAIL: {name} ({type(error).__name__}: {error})", flush=True)
        else:
            results.append({"name": name, "status": "passed"})
            print(f"PASS: {name}", flush=True)
        results[-1]["seconds"] = round(perf_counter() - started, 3)
    failed = sum(row["status"] == "failed" for row in results)
    path = ROOT / "results.json"
    path.write_text(json.dumps({"passed": len(results) - failed, "failed": failed,
        "limitations": "Mock HTTP/DNS, synthetic HTML and isolated caches; not live vendor compatibility, retrieval quality or model certification.", "checks": results}, indent=2), encoding="utf-8")
    print(f"\nSUMMARY: {len(results) - failed}/{len(results)} passed; {failed} failed.")
    print("Full results:", path)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
