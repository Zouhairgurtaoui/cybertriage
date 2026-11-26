"""Fuse semantic, lexical and exact-identifier evidence with per-call provenance."""

import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime
from hashlib import sha256
from threading import RLock
from urllib.parse import urlsplit

from cybertriage.application.policies.lexical_retrieval import BM25PassageIndex, tokens
from cybertriage.application.ports.retrieval import KnowledgeCandidateSource
from cybertriage.domain.retrieval import IndexedPassage, KnowledgeRetrievalError, RetrievalContext, RetrievalOutcome
from cybertriage.domain.triage import RetrievedReference


class HybridKnowledgeRetriever:
    def __init__(self, sources: tuple[KnowledgeCandidateSource, ...]):
        if not sources:
            raise ValueError("At least one candidate source is required.")
        self._sources = sources
        self._lock = RLock()
        self._corpus: dict[str, IndexedPassage] | None = None
        self._active: dict[str, IndexedPassage] = {}
        self._source_ids: tuple[frozenset[str], ...] = ()
        self._lexical: BM25PassageIndex | None = None
        self._corpus_hash = ""

    def _initialize(self) -> None:
        with self._lock:
            if self._corpus is not None:
                return
            corpus: dict[str, IndexedPassage] = {}
            source_ids = []
            total_bytes = 0
            for source in self._sources:
                batch = source.snapshot()
                ids = set()
                for passage in batch:
                    key = passage.reference.chunk_id
                    if passage.retrieved_at.utcoffset() is None or not passage.reference.text.strip() or len(passage.reference.text) > 4000:
                        raise KnowledgeRetrievalError("Knowledge corpus contains invalid passage metadata or text.")
                    if key in corpus and corpus[key] != passage:
                        raise KnowledgeRetrievalError("Conflicting knowledge chunk identity across collections.")
                    if key in ids:
                        raise KnowledgeRetrievalError("A collection contains duplicate chunk identities.")
                    ids.add(key)
                    if key not in corpus:
                        total_bytes += len(json.dumps(asdict(passage), default=str, ensure_ascii=False).encode("utf-8"))
                    corpus[key] = passage
                    if len(corpus) > 20000 or total_bytes > 64 * 1024 * 1024:
                        raise KnowledgeRetrievalError("Knowledge corpus exceeds 20000 passages or 64 MiB of serialized content.")
                source_ids.append(frozenset(ids))
            versions: dict[tuple[str, str], dict[tuple[str, str, datetime], datetime]] = defaultdict(dict)
            for passage in corpus.values():
                document = passage.source_name, passage.document_id
                revision = passage.source_revision, passage.document_hash, passage.retrieved_at
                previous = versions[document].get(revision)
                if previous is None or passage.retrieved_at > previous:
                    versions[document][revision] = passage.retrieved_at
            latest = {}
            for document, revisions in versions.items():
                newest = max(revisions.values())
                selected = [revision for revision, timestamp in revisions.items() if timestamp == newest]
                if len(selected) != 1:
                    raise KnowledgeRetrievalError("Knowledge document has ambiguous latest fetched revisions.")
                latest[document] = selected[0]
            active = {key: passage for key, passage in corpus.items()
                      if (passage.source_revision, passage.document_hash, passage.retrieved_at) == latest[(passage.source_name, passage.document_id)]}
            positions = set()
            for passage in active.values():
                slot = passage.source_name, passage.document_id, passage.position
                if slot in positions:
                    raise KnowledgeRetrievalError("Latest knowledge snapshot has conflicting chunk positions.")
                positions.add(slot)
            lexical = BM25PassageIndex(tuple(active.values()))
            digest = sha256()
            for key, passage in sorted(corpus.items()):
                digest.update(json.dumps(asdict(passage), default=str, sort_keys=True).encode("utf-8"))
                digest.update(b"\n")
            # Publish only after every source and index has loaded successfully.
            self._active, self._source_ids, self._lexical = active, tuple(source_ids), lexical
            self._corpus_hash = digest.hexdigest()
            self._corpus = corpus

    @staticmethod
    def _compatible(passage: IndexedPassage, platform: str | None) -> bool:
        hosts = {value.casefold() for value in passage.platforms} & {"windows", "linux", "macos"}
        return platform is None or not hosts or platform in hosts

    @staticmethod
    def _exact(passage: IndexedPassage, query: str, context: RetrievalContext) -> tuple[str, ...]:
        reasons = []
        requested = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", query.upper()))
        named = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", passage.reference.title.upper()))
        if requested & named:
            reasons.append("explicit_technique_id")
        event = context.event
        if (event is not None and event.provider == "Microsoft-Windows-Security-Auditing" and event.channel == "Security"
                and passage.source_name == "microsoft_learn"):
            path = urlsplit(passage.reference.source_url).path.rstrip("/")
            title = passage.reference.title
            if path.endswith(f"/event-{event.event_id}") or re.match(rf"^{event.event_id}(?:\D|$)", title):
                reasons.append("exact_security_event_document")
        return tuple(reasons)

    def retrieve(self, query: str, k: int = 3) -> list[RetrievedReference]:
        return list(self.retrieve_for(query, RetrievalContext(), k).references)

    def retrieve_for(self, query: str, context: RetrievalContext, k: int = 3) -> RetrievalOutcome:
        if (not isinstance(query, str) or not query.strip() or len(query.encode("utf-8")) > 4000
                or type(k) is not int or not 1 <= k <= 20):
            raise ValueError("Supply a focused query of 1..4000 UTF-8 bytes and k from 1 to 20.")
        if not isinstance(context, RetrievalContext):
            raise ValueError("A typed retrieval context is required.")
        if any(ord(character) < 32 and character not in "\n\r\t" for character in query):
            raise ValueError("Knowledge query contains unsupported control characters.")
        effective = query.strip()
        if context.event_description and context.event_description.casefold() not in effective.casefold():
            effective += "\n" + context.event_description
        if context.host_platform and context.host_platform not in set(tokens(effective)):
            effective += "\n" + context.host_platform
        if len(set(tokens(effective))) > 256:
            raise ValueError("Knowledge query contains too many distinct terms; provide a focused query.")
        self._initialize()
        corpus, lexical = self._corpus, self._lexical
        if corpus is None or lexical is None:
            raise KnowledgeRetrievalError("Knowledge index did not initialize.")
        allowed = {key for key, passage in self._active.items() if self._compatible(passage, context.host_platform)}
        dense_ranks: dict[str, int] = {}
        ignored = Counter()
        for source, source_ids in zip(self._sources, self._source_ids):
            if not source_ids & allowed:
                continue
            candidates = source.dense_candidates(effective, limit=20)
            if len(candidates) > 20:
                raise KnowledgeRetrievalError("Semantic source exceeded its candidate budget.")
            for rank, passage in enumerate(candidates, 1):
                key = passage.reference.chunk_id
                if key not in source_ids or corpus.get(key) != passage:
                    raise KnowledgeRetrievalError("Knowledge changed after its snapshot; finish ingestion and restart analysis.")
                if key not in allowed:
                    ignored["ineligible_dense_candidate"] += 1
                    continue
                dense_ranks[key] = min(rank, dense_ranks.get(key, rank))
        lexical_ranks = {key: rank for rank, (key, _) in enumerate(lexical.rank(effective, allowed, 20), 1)}
        anchors = {key: reasons for key in allowed if (reasons := self._exact(self._active[key], query, context))}
        candidates = set(dense_ranks) | set(lexical_ranks) | set(anchors)
        def score(key: str) -> float:
            return ((1 / (60 + dense_ranks[key]) if key in dense_ranks else 0)
                    + (1 / (60 + lexical_ranks[key]) if key in lexical_ranks else 0)
                    + (3 / 61 if key in anchors else 0))
        ordered = sorted(candidates, key=lambda key: (-score(key), self._active[key].reference.source_url,
                                                    self._active[key].position, key))
        selected, used_texts = [], set()
        budget_excluded = set()
        document_counts: Counter[str] = Counter()
        byte_count = 0
        for maximum in (1, 2):
            for key in ordered:
                passage = self._active[key]
                reference = passage.reference
                document = reference.source_url.rstrip("/")
                body = reference.text.removeprefix(reference.title).lstrip()
                text_hash = sha256(" ".join(body.split()).encode("utf-8")).hexdigest()
                if key in selected or text_hash in used_texts or document_counts[document] >= maximum:
                    continue
                size = len(reference.text.encode("utf-8"))
                if byte_count + size > 12000:
                    budget_excluded.add(key)
                    continue
                selected.append(key)
                used_texts.add(text_hash)
                document_counts[document] += 1
                byte_count += size
                if len(selected) == k:
                    break
            if len(selected) == k:
                break
        if budget_excluded:
            ignored["reference_byte_budget"] = len(budget_excluded)
        trace = {
            "version": 1, "policy": "hybrid-bm25-rrf-v1", "corpus_sha256": self._corpus_hash,
            "query_sha256": sha256(query.encode("utf-8")).hexdigest(),
            "effective_query_sha256": sha256(effective.encode("utf-8")).hexdigest(),
            "context": {"event": asdict(context.event) if context.event else None, "host_platform": context.host_platform,
                        "catalogue_description_used": context.event_description is not None},
            "corpus_passages": len(corpus), "active_passages": len(self._active), "eligible_passages": len(allowed),
            "platform_metadata_unknown": sum(not passage.platforms for passage in self._active.values()),
            "old_snapshot_passages_excluded": len(corpus) - len(self._active),
            "platform_passages_excluded": len(self._active) - len(allowed),
            "candidate_count": len(candidates), "requested_k": k, "returned_count": len(selected),
            "selected": [{"chunk_id": key, "source_url": self._active[key].reference.source_url,
                          "document_id": self._active[key].document_id, "source_revision": self._active[key].source_revision,
                          "document_hash": self._active[key].document_hash, "retrieved_at": self._active[key].retrieved_at.isoformat(),
                          "platforms": list(self._active[key].platforms), "dense_rank": dense_ranks.get(key),
                          "lexical_rank": lexical_ranks.get(key), "exact_matches": list(anchors.get(key, ())),
                          "fusion_score": score(key)} for key in selected],
            "limits": {"dense_candidates_per_collection": 20, "lexical_candidates": 20,
                       "max_passages_per_document": 2, "reference_bytes": 12000},
            "ignored": dict(ignored),
            "interpretation": "Ranks are retrieval heuristics, not probabilities or evidence of an attack. Unknown platform metadata is retained. A bounded candidate pool and incomplete source corpus limit recall; selected references still require relevance review.",
        }
        trace_json = json.dumps(trace, sort_keys=True, ensure_ascii=False, allow_nan=False)
        if len(trace_json.encode("utf-8")) > 128 * 1024:
            raise KnowledgeRetrievalError("Retrieval provenance exceeds its 128 KiB budget.")
        return RetrievalOutcome(tuple(self._active[key].reference for key in selected), trace_json)
