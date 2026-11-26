"""Refresh public documents and augment local references without changing Chroma."""

import json
import logging
from dataclasses import asdict, replace
from datetime import datetime, timedelta
from time import monotonic
from typing import Callable

from cybertriage.application.policies.lexical_retrieval import BM25PassageIndex
from cybertriage.application.policies.live_web import plan_web_targets, validate_target_url
from cybertriage.application.ports.knowledge import KnowledgeChunker
from cybertriage.application.ports.live_web import PublicDocumentCache, PublicDocumentFetcher, PublicDocumentParser
from cybertriage.application.ports.retrieval import ContextualKnowledgeRetriever
from cybertriage.domain.live_web import (
    WEB_DOCUMENT_POLICY, LiveWebSettings, WebCacheEntry, WebCacheError, WebFetchError, WebKnowledgeError,
    WebLookup, WebRequestBudget, WebTarget, WebTransientError, utc_now,
)
from cybertriage.domain.retrieval import IndexedPassage, KnowledgeRetrievalError, RetrievalContext, RetrievalOutcome
from cybertriage.domain.triage import RetrievedReference

logger = logging.getLogger(__name__)


class LiveDocumentReader:
    def __init__(self, cache: PublicDocumentCache, fetcher: PublicDocumentFetcher, parser: PublicDocumentParser,
                 settings: LiveWebSettings, clock: Callable[[], datetime] = utc_now):
        self._cache, self._fetcher, self._parser = cache, fetcher, parser
        self._settings, self._clock = settings, clock

    def _cached(self, target: WebTarget, now: datetime) -> WebCacheEntry | None:
        entry = self._cache.get(target.key)
        if entry is None:
            return None
        validate_target_url(target, entry.canonical_url)
        if entry.target_key != target.key or entry.validated_at > now:
            raise WebCacheError("Cached documentation identity or clock is inconsistent.")
        document = entry.document
        if document is not None and (document.document_id != f"live:{target.source}:{target.identifier}"
                or document.source_name != f"live_{target.source}"
                or document.source_revision != f"{WEB_DOCUMENT_POLICY}:sha256:{document.content_hash}"):
            raise WebCacheError("Cached documentation provenance is inconsistent.")
        return entry

    def _stale(self, entry: WebCacheEntry | None, now: datetime) -> bool:
        return (self._settings.allow_stale_on_error and entry is not None and entry.document is not None
                and entry.expires_at <= now <= entry.expires_at + timedelta(seconds=self._settings.max_stale_seconds))

    def read(self, target: WebTarget, budget: WebRequestBudget) -> WebLookup:
        now, used = self._clock(), budget.used
        diagnostics: list[str] = []
        token = None
        defer_release = False
        cached = None
        outcome = None
        try:
            cached = self._cached(target, now)
            if cached is not None and now < cached.expires_at:
                return WebLookup(target, "fresh_cache" if cached.document else "not_found", cached)
            token = self._cache.claim(target.key, now)
            # Another writer can have published between the first read and claim.
            refreshed = self._cached(target, self._clock())
            if refreshed is not None and self._clock() < refreshed.expires_at:
                outcome = WebLookup(target, "fresh_cache" if refreshed.document else "not_found", refreshed)
            elif token is None:
                outcome = WebLookup(target, "stale_refresh_in_progress" if self._stale(refreshed, self._clock()) else "refresh_in_progress",
                                    refreshed if self._stale(refreshed, self._clock()) else None)
            else:
                cached = refreshed
                urls = list(dict.fromkeys(([cached.canonical_url] if cached is not None and cached.document else []) + list(target.urls)))
                response = None
                parsed_document = None
                parse_failed = False
                for url in urls:
                    validate_target_url(target, url)
                    conditional = cached is not None and cached.document is not None and cached.canonical_url == url
                    response = self._fetcher.fetch(url, budget, etag=cached.etag if conditional else None,
                                                   last_modified=cached.last_modified if conditional else None)
                    validate_target_url(target, response.url)
                    if response.status in {404, 410}:
                        continue
                    if response.status not in {200, 304}:
                        raise WebFetchError("Unexpected public document response.")
                    if response.status == 200:
                        try:
                            parsed_document = self._parser.parse(target, response, self._clock())
                        except WebFetchError:
                            parse_failed = True
                            diagnostics.append("article_parse_failed")
                            continue
                    break
                now = self._clock()
                if response is None:
                    raise WebFetchError("No public document route was available.")
                if response.status in {404, 410}:
                    if parse_failed:
                        raise WebFetchError("Approved responses did not contain a validated article.")
                    entry = WebCacheEntry(target.key, response.url, None, now, now,
                                          now + timedelta(seconds=self._settings.not_found_ttl_seconds))
                    status = "not_found"
                elif response.status == 304:
                    if cached is None or cached.document is None or response.url != cached.canonical_url:
                        raise WebFetchError("A 304 response has no matching cached document.")
                    entry = replace(cached, validated_at=now, expires_at=now + timedelta(seconds=self._settings.ttl_seconds),
                                    etag=response.etag or cached.etag, last_modified=response.last_modified or cached.last_modified)
                    status = "revalidated"
                else:
                    if parsed_document is None:
                        raise WebFetchError("No approved response contained a validated article.")
                    document = parsed_document
                    entry = WebCacheEntry(target.key, document.source_url, document, document.retrieved_at, now,
                        now + timedelta(seconds=self._settings.ttl_seconds), response.etag, response.last_modified)
                    status = "network"
                try:
                    self._cache.save(entry, token, self._clock())
                except WebCacheError:
                    diagnostics.append("cache_write_failed")
                    defer_release = True
                outcome = WebLookup(target, status, entry)
        except WebTransientError as error:
            defer_release = True
            now = self._clock()
            outcome = WebLookup(target, "stale_cache" if self._stale(cached, now) else "error",
                                cached if self._stale(cached, now) else None, (error.code,))
        except WebKnowledgeError as error:
            outcome = WebLookup(target, "error", None, (error.code,))
        finally:
            if token is not None and not defer_release:
                try:
                    self._cache.release(target.key, token)
                except WebCacheError:
                    diagnostics.append("cache_release_failed")
        if outcome is None:
            raise KnowledgeRetrievalError("Live document lookup ended without an outcome.")
        return replace(outcome, diagnostic_codes=(*outcome.diagnostic_codes, *diagnostics), http_requests=budget.used - used)


class LiveWebKnowledgeRetriever:
    def __init__(self, local: ContextualKnowledgeRetriever, reader: LiveDocumentReader, chunker: KnowledgeChunker,
                 settings: LiveWebSettings, *, chunk_input_limit: int = 150000):
        if type(chunk_input_limit) is not int or not 1 <= chunk_input_limit <= 150000:
            raise ValueError("Invalid live chunk input limit.")
        self._local, self._reader, self._chunker, self._settings = local, reader, chunker, settings
        self._chunk_input_limit = chunk_input_limit

    def retrieve(self, query: str, k: int = 3) -> list[RetrievedReference]:
        return list(self.retrieve_for(query, RetrievalContext(), k).references)

    def retrieve_for(self, query: str, context: RetrievalContext, k: int = 3) -> RetrievalOutcome:
        # Source failures in the local corpus remain fatal, rather than becoming web-only reports.
        local = self._local.retrieve_for(query, context, k)
        if not self._settings.enabled:
            return local
        targets = plan_web_targets(query, context, local.references, self._settings)
        budget = WebRequestBudget(self._settings.max_http_requests, monotonic() + 30)
        lookups = tuple(self._reader.read(target, budget) for target in targets)
        for lookup in lookups:
            level = logging.WARNING if lookup.status.startswith("stale") or lookup.status in {"error", "refresh_in_progress"} or lookup.diagnostic_codes else logging.INFO
            logger.log(level, "Public knowledge source=%s identifier=%s status=%s codes=%s",
                       lookup.target.source, lookup.target.identifier, lookup.status, ",".join(lookup.diagnostic_codes) or "none")
        web_references: list[RetrievedReference] = []
        incompatible_urls = set()
        diagnostics = []
        effective = query + ("\n" + context.event_description if context.event_description else "")
        for lookup in lookups:
            entry = lookup.entry
            if entry is None or entry.document is None:
                continue
            document = entry.document
            if len(document.text) > self._chunk_input_limit:
                diagnostics.append("live_chunk_input_budget_exceeded")
                continue
            hosts = {name.casefold() for name in document.platforms} & {"windows", "linux", "macos"}
            if context.host_platform is not None and hosts and context.host_platform not in hosts:
                if not lookup.status.startswith("stale"):
                    incompatible_urls.add(document.source_url.rstrip("/"))
                continue
            chunks = self._chunker.split(document)
            if not 1 <= len(chunks) <= 256 or any(len(chunk.text) > 3000 for chunk in chunks):
                diagnostics.append("live_chunk_budget_exceeded")
                continue
            passages = tuple(IndexedPassage(RetrievedReference(chunk.chunk_id, document.title, document.source_url,
                f"{document.title}\n\n{chunk.text}"), document.source_name, document.document_id, document.source_revision,
                document.content_hash, document.retrieved_at, chunk.position, document.platforms) for chunk in chunks)
            ranked = BM25PassageIndex(passages).rank(effective + "\n" + lookup.target.identifier,
                                                   {passage.reference.chunk_id for passage in passages}, limit=1)
            chosen = next((passage for passage in passages if ranked and passage.reference.chunk_id == ranked[0][0]), passages[0])
            provenance = json.dumps({"kind": "live_web", "source": lookup.target.source, "identifier": lookup.target.identifier,
                "lookup_status": lookup.status, "stale": lookup.status.startswith("stale"), "fetched_at": entry.fetched_at.isoformat(),
                "validated_at": entry.validated_at.isoformat(), "expires_at": entry.expires_at.isoformat(),
                "content_sha256": document.content_hash, "source_revision": document.source_revision,
                "platforms": list(document.platforms)}, sort_keys=True)
            if len(provenance.encode("utf-8")) > 4096:
                diagnostics.append("live_provenance_budget_exceeded")
                continue
            web_references.append(replace(chosen.reference, provenance_json=provenance))
        local_eligible = [reference for reference in local.references if reference.source_url.rstrip("/") not in incompatible_urls]
        # Fresh exact-source context leads; stale cache is retained only after available local context.
        fresh = [reference for reference in web_references if not json.loads(reference.provenance_json or "{}").get("stale")]
        stale = [reference for reference in web_references if reference not in fresh]
        selected, urls, ids = [], set(), set()
        size = 0
        for reference in (*fresh, *local_eligible, *stale):
            url = reference.source_url.rstrip("/")
            if reference.chunk_id in ids or url in urls or len(reference.text) > 4000:
                continue
            amount = len(reference.text.encode("utf-8"))
            if size + amount > 12000:
                continue
            selected.append(reference)
            ids.add(reference.chunk_id)
            urls.add(url)
            size += amount
            if len(selected) == k:
                break
        if not web_references and not incompatible_urls:
            selected = list(local.references)
        trace = {"version": 1, "policy": "local-plus-public-web-v1", "local_candidate_trace": json.loads(local.trace_json),
            "web": {"enabled": self._settings.enabled, "target_count": len(targets), "http_requests": budget.used,
                    "lookups": [{"source": lookup.target.source, "identifier": lookup.target.identifier, "status": lookup.status,
                        "canonical_url": lookup.entry.canonical_url if lookup.entry else None, "http_requests": lookup.http_requests,
                        "requested_urls": list(lookup.target.urls),
                        "fetched_at": lookup.entry.fetched_at.isoformat() if lookup.entry else None,
                        "validated_at": lookup.entry.validated_at.isoformat() if lookup.entry else None,
                        "platforms": list(lookup.entry.document.platforms) if lookup.entry and lookup.entry.document else [],
                        "content_sha256": lookup.entry.document.content_hash if lookup.entry and lookup.entry.document else None,
                        "diagnostic_codes": list(lookup.diagnostic_codes)} for lookup in lookups],
                    "diagnostic_codes": diagnostics, "local_platform_exclusions": len(local.references) - len(local_eligible),
                    "selection": "fresh exact-identifier web context, local context, then permitted stale cache; one excerpt per URL",
                    "privacy": "Only public identifier routes are requested; incident text and original query are not submitted to an internet search API."},
            "selected": [{"chunk_id": reference.chunk_id, "source_url": reference.source_url,
                          "provenance": json.loads(reference.provenance_json) if reference.provenance_json else None} for reference in selected],
            "returned_count": len(selected), "requested_k": k,
            "interpretation": "Public documents are background knowledge, not incident observations. Missing pages and refresh errors do not establish absence of attack activity. Freshness records describe retrieval/validation, not a guarantee that the publisher is current."}
        trace_json = json.dumps(trace, ensure_ascii=False, sort_keys=True, allow_nan=False)
        if len(trace_json.encode("utf-8")) > 256 * 1024:
            raise KnowledgeRetrievalError("Combined retrieval trace exceeds its 256 KiB budget.")
        return RetrievalOutcome(tuple(selected), trace_json)
