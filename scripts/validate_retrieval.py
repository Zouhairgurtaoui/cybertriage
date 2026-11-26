"""Offline retrieval boundaries using in-memory source/store/model substitutes.

No Chroma database, embeddings, chat model, network, or operational alert store
is opened. Results are written only beneath ignored data/validation.
"""

import json
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from cybertriage.adapters.storage.chroma import ChromaKnowledgeIndex
from cybertriage.application.policies.lexical_retrieval import tokens
from cybertriage.application.services.knowledge_retrieval import HybridKnowledgeRetriever
from cybertriage.application.use_cases.analyze_alert import AnalyzeAlert
from cybertriage.domain.knowledge import KnowledgeChunk, KnowledgeDocument
from cybertriage.domain.retrieval import IndexedPassage, KnowledgeRetrievalError, RetrievalContext
from cybertriage.domain.security_event import EventIdentity, SecurityEventDefinition
from cybertriage.domain.triage import RetrievedReference

ROOT = Path.cwd() / "data" / "validation" / f"retrieval-{uuid4().hex}"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
WINDOWS = EventIdentity("Microsoft-Windows-Security-Auditing", "Security", 4625)
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


def passage(key, body, *, title=None, document=None, position=0, platforms=(), at=BASE, revision="revision-1",
            source="mitre_attack", url=None):
    document = document or key
    title = title or key
    reference = RetrievedReference(sha256(key.encode()).hexdigest(), title,
        url or f"https://attack.mitre.org/techniques/{document}", f"{title}\n\n{body}")
    return IndexedPassage(reference, source, document, revision, sha256(f"{document}:{revision}".encode()).hexdigest(), at, position, platforms)


class Source:
    def __init__(self, corpus, dense=None):
        self.corpus = tuple(corpus)
        self.dense = tuple(dense if dense is not None else corpus)
        self.snapshots = 0
        self.queries = []

    def snapshot(self):
        self.snapshots += 1
        return self.corpus

    def dense_candidates(self, query, limit):
        self.queries.append((query, limit))
        return self.dense[:limit]


@check("Keyword support can outrank semantic-only candidates without comparing distance scales")
def hybrid_ranking():
    irrelevant = passage("irrelevant", "Launch an application when a desktop starts.")
    relevant = passage("relevant", "Investigate disabled accounts and failed authentication attempts.")
    source = Source([irrelevant, relevant], dense=[irrelevant, relevant])
    result = HybridKnowledgeRetriever((source,)).retrieve_for("disabled accounts failed authentication", RetrievalContext(), 1)
    assert result.references[0].chunk_id == relevant.reference.chunk_id
    row = json.loads(result.trace_json)["selected"][0]
    assert row["dense_rank"] == 2 and row["lexical_rank"] == 1


@check("Explicit macOS references are filtered for Windows; unknown platform metadata remains visible")
def platform_filter():
    mac = passage("mac", "Failed authentication with macOS login items.", platforms=("macos",))
    windows = passage("windows", "Investigate failed authentication.", platforms=("windows",))
    unknown = passage("unknown", "Generic authentication context.")
    result = HybridKnowledgeRetriever((Source([mac, windows, unknown]),)).retrieve_for("failed authentication", RetrievalContext(event=WINDOWS), 3)
    ids = {row.chunk_id for row in result.references}
    assert mac.reference.chunk_id not in ids and windows.reference.chunk_id in ids and unknown.reference.chunk_id in ids
    trace = json.loads(result.trace_json)
    assert trace["platform_passages_excluded"] == 1 and trace["platform_metadata_unknown"] == 1


@check("All-incompatible or empty corpora return no background references without embedding calls")
def empty_eligible():
    for corpus in ([], [passage("mac", "macOS startup", platforms=("macos",))]):
        source = Source(corpus)
        outcome = HybridKnowledgeRetriever((source,)).retrieve_for("Windows authentication", RetrievalContext(event=WINDOWS), 3)
        assert outcome.references == () and source.queries == []


@check("Exact event documents prioritize the correct provider/channel and retain their own citations")
def exact_event():
    generic = passage("generic", "Authentication and accounts.")
    exact = passage("event", "Failure audit overview.", title="4625(S): An account failed to log on.", source="microsoft_learn",
                    url="https://learn.microsoft.com/en-us/windows/security/event-4625")
    source = Source([generic, exact], dense=[generic])
    outcome = HybridKnowledgeRetriever((source,)).retrieve_for("authentication", RetrievalContext(event=WINDOWS), 1)
    assert outcome.references[0].chunk_id == exact.reference.chunk_id
    assert "exact_security_event_document" in json.loads(outcome.trace_json)["selected"][0]["exact_matches"]
    sysmon = EventIdentity("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", 4625)
    outcome = HybridKnowledgeRetriever((source,)).retrieve_for("authentication", RetrievalContext(event=sysmon), 2)
    assert all("exact_security_event_document" not in row["exact_matches"] for row in json.loads(outcome.trace_json)["selected"])


@check("Explicit ATT&CK identifiers remain intact in tokenization and exact ranking")
def technique_identifier():
    exact = passage("technique", "Account manipulation guidance.", title="T1098.007: Additional Local or Domain Groups")
    other = passage("other", "General group guidance.")
    assert "t1098.007" in tokens("Explain T1098.007")
    outcome = HybridKnowledgeRetriever((Source([exact, other], dense=[other]),)).retrieve_for("T1098.007", RetrievalContext(), 1)
    assert outcome.references[0].chunk_id == exact.reference.chunk_id


@check("Matched later chunks are not replaced by a document's opening chunk")
def no_lead_replacement():
    lead = passage("lead", "General introduction.", document="guide", position=0)
    tail = passage("tail", "Investigate disabled account authentication.", document="guide", position=1)
    outcome = HybridKnowledgeRetriever((Source([lead, tail], dense=[tail]),)).retrieve_for("disabled account authentication", RetrievalContext(), 1)
    assert outcome.references[0].chunk_id == tail.reference.chunk_id and outcome.references[0].text == tail.reference.text


@check("Repeated excerpts and document monopolies do not fill all citation slots")
def diversity():
    repeated = [passage(f"same-{i}", f"Authentication guidance detail {i}.", document="one-guide", position=i) for i in range(4)]
    other = passage("other", "Authentication checks on a second source.")
    outcome = HybridKnowledgeRetriever((Source([*repeated, other]),)).retrieve_for("authentication guidance", RetrievalContext(), 3)
    assert sum(row.source_url.endswith("one-guide") for row in outcome.references) <= 2
    assert any(row.chunk_id == other.reference.chunk_id for row in outcome.references)
    same_a = passage("copy-a", "Same authentication passage.")
    same_b = passage("copy-b", "Same authentication passage.")
    outcome = HybridKnowledgeRetriever((Source([same_a, same_b]),)).retrieve_for("authentication", RetrievalContext(), 3)
    assert len(outcome.references) == 1


@check("Latest fetched document snapshots exclude older revisions and older chunking layouts")
def latest_snapshot():
    old = passage("old", "Authentication old guidance.", document="same-doc")
    new = passage("new", "Authentication revised guidance.", document="same-doc", revision="revision-2", at=BASE + timedelta(hours=1))
    outcome = HybridKnowledgeRetriever((Source([old, new]),)).retrieve_for("authentication", RetrievalContext(), 3)
    assert [row.chunk_id for row in outcome.references] == [new.reference.chunk_id]
    assert json.loads(outcome.trace_json)["old_snapshot_passages_excluded"] == 1
    newer_layout = replace(new, reference=replace(new.reference, chunk_id="new-layout"), retrieved_at=BASE + timedelta(hours=2))
    outcome = HybridKnowledgeRetriever((Source([new, newer_layout]),)).retrieve_for("authentication", RetrievalContext(), 3)
    assert [row.chunk_id for row in outcome.references] == ["new-layout"]


@check("Conflicting chunk IDs and ambiguous latest document versions fail visibly")
def conflicts():
    item = passage("same", "Authentication guidance.")
    altered = replace(item, reference=replace(item.reference, text="Different body"))
    expect(KnowledgeRetrievalError, lambda: HybridKnowledgeRetriever((Source([item]), Source([altered]))).retrieve("authentication", 1))
    other_revision = passage("revision", "Another body", document=item.document_id, revision="other-revision")
    expect(KnowledgeRetrievalError, lambda: HybridKnowledgeRetriever((Source([item, other_revision]),)).retrieve("authentication", 1))


@check("Source failures and semantic results outside the captured corpus are not empty successes")
def source_errors():
    class Broken(Source):
        def dense_candidates(self, query, limit):
            raise KnowledgeRetrievalError("Synthetic semantic failure")
    item = passage("valid", "Authentication evidence.")
    expect(KnowledgeRetrievalError, lambda: HybridKnowledgeRetriever((Broken([item]),)).retrieve("authentication", 1))
    foreign = passage("foreign", "Authentication elsewhere.")
    expect(KnowledgeRetrievalError, lambda: HybridKnowledgeRetriever((Source([item], dense=[foreign]),)).retrieve("authentication", 1))
    class BrokenSnapshot(Source):
        def snapshot(self):
            raise KnowledgeRetrievalError("Synthetic snapshot failure")
    expect(KnowledgeRetrievalError, lambda: HybridKnowledgeRetriever((BrokenSnapshot([]),)).retrieve("authentication", 1))


@check("Changed indexes require a new snapshot instead of mixing old lexical and new semantic data")
def changed_index():
    item = passage("valid", "Authentication guidance.")
    source = Source([item])
    retriever = HybridKnowledgeRetriever((source,))
    retriever.retrieve("authentication", 1)
    source.dense = (replace(item, retrieved_at=BASE + timedelta(days=1)),)
    expect(KnowledgeRetrievalError, lambda: retriever.retrieve("authentication", 1))


@check("Invalid queries, contradictory context and oversized passages fail before semantic lookup")
def input_limits():
    source = Source([passage("valid", "Authentication.")])
    retriever = HybridKnowledgeRetriever((source,))
    for query, k in (("", 3), ("a" * 4001, 3), ("query", True), ("query", 21), ("query\x00", 3)):
        expect(ValueError, lambda: retriever.retrieve(query, k))
    expect(ValueError, lambda: RetrievalContext(event=WINDOWS, platform="macos"))
    assert source.queries == []
    huge = passage("huge", "x" * 5000)
    expect(KnowledgeRetrievalError, lambda: HybridKnowledgeRetriever((Source([huge]),)).retrieve("query", 1))


@check("Reference byte budgets preserve whole chunks rather than truncating text under an existing citation")
def reference_budget():
    values = [passage(f"p{i}", f"authentication {i} " + "x" * 3850) for i in range(5)]
    outcome = HybridKnowledgeRetriever((Source(values),)).retrieve_for("authentication", RetrievalContext(), 5)
    assert len(outcome.references) < 5
    assert sum(len(row.text.encode()) for row in outcome.references) <= 12000
    original = {row.reference.chunk_id: row.reference.text for row in values}
    assert all(row.text == original[row.chunk_id] for row in outcome.references)


@check("Query-local provenance and platform selection stay isolated under concurrent retrieval")
def concurrent_contexts():
    windows = passage("windows", "Authentication Windows.", platforms=("windows",))
    mac = passage("mac", "Authentication macOS.", platforms=("macos",))
    source = Source([windows, mac])
    retriever = HybridKnowledgeRetriever((source,))
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda platform: retriever.retrieve_for("authentication", RetrievalContext(platform=platform), 1), ["windows", "macos"]))
    assert outcomes[0].references[0].chunk_id == windows.reference.chunk_id
    assert outcomes[1].references[0].chunk_id == mac.reference.chunk_id
    assert json.loads(outcomes[0].trace_json)["context"]["host_platform"] == "windows"
    assert json.loads(outcomes[1].trace_json)["context"]["host_platform"] == "macos"
    assert source.snapshots == 1


@check("Metadata refresh preserves existing chunk IDs and does not send documents or embeddings to update")
def metadata_upgrade():
    document = KnowledgeDocument("doc", "microsoft_learn", "Windows event", "Account guidance.",
        "https://learn.microsoft.com/en-us/windows/event-4625", "revision", BASE, ("Windows",))
    chunk = KnowledgeChunk(sha256(b"chunk").hexdigest(), document, 0, document.text)
    prepared = ChromaKnowledgeIndex._to_document(chunk)
    old_metadata = dict(prepared.metadata); old_metadata.pop("platforms_json")
    updates = []
    class Store:
        def get(self, **kwargs):
            return {"ids": [chunk.chunk_id], "documents": [prepared.page_content], "metadatas": [old_metadata]}
        def add_documents(self, **kwargs):
            raise AssertionError("Existing text must not be embedded again")
    class Collection:
        def update(self, *, ids, metadatas):
            updates.append((ids, metadatas))
    index = object.__new__(ChromaKnowledgeIndex)
    setattr(index, "_store", Store())
    setattr(index, "_collection", Collection())
    assert index.add_chunks([chunk]) == 0
    assert updates[0][0] == [chunk.chunk_id]
    assert json.loads(updates[0][1][0]["platforms_json"]) == ["Windows"]


@check("Legacy Chroma metadata stays readable and malformed platform values fail")
def metadata_reader():
    document = KnowledgeDocument("doc", "microsoft_learn", "Event", "Authentication.",
        "https://learn.microsoft.com/en-us/windows/event-4625", "revision", BASE)
    prepared = ChromaKnowledgeIndex._to_document(KnowledgeChunk("chunk", document, 0, document.text))
    prepared.metadata.pop("platforms_json")
    assert ChromaKnowledgeIndex._passage(prepared).platforms == ()
    prepared.metadata["platforms_json"] = '{"bad":"type"}'
    expect(KnowledgeRetrievalError, lambda: ChromaKnowledgeIndex._passage(prepared))


@check("Analysis preserves exact event catalogue anchors and serializes retrieval provenance; legacy ports still work")
def analysis_integration():
    class Catalog:
        def lookup(self, provider, channel, event_id):
            return SecurityEventDefinition(provider, channel, event_id, "A failed account logon.",
                "https://learn.microsoft.com/en-us/windows/event-4625", "fixture-catalogue")
    class Model:
        def analyze(self, evidence, references):
            self.references = references
            return "Synthetic report; not a semantic evaluation."
    value = passage("auth", "Failed account logon investigation.", platforms=("windows",))
    retriever = HybridKnowledgeRetriever((Source([value]),))
    result = AnalyzeAlert(retriever, Model(), catalog=Catalog(), contextual_retriever=retriever).execute("Fixture evidence.", event=WINDOWS)
    assert result.references[0].chunk_id.startswith("catalog:")
    assert json.loads(result.retrieval_trace_json)["context"]["host_platform"] == "windows"
    assert json.loads(json.dumps(asdict(result)))["retrieval_trace_json"] == result.retrieval_trace_json
    class Legacy:
        def retrieve(self, query, k):
            return [value.reference]
    assert AnalyzeAlert(Legacy(), Model()).execute("Fixture evidence.").retrieval_trace_json is None


def main():
    if not __debug__ or not Path("pyproject.toml").is_file():
        raise SystemExit("Run from the project root without -O.")
    ROOT.mkdir(parents=True, exist_ok=False)
    print("Validation output directory:", ROOT, flush=True)
    results = []
    for name, function in CHECKS:
        started = time.perf_counter()
        try:
            function()
        except Exception as error:
            results.append({"name": name, "status": "failed", "error_type": type(error).__name__, "details": str(error), "traceback": traceback.format_exc()})
            print(f"FAIL: {name} ({type(error).__name__}: {error})", flush=True)
        else:
            results.append({"name": name, "status": "passed"})
            print(f"PASS: {name}", flush=True)
        results[-1]["seconds"] = round(time.perf_counter() - started, 3)
    failed = sum(row["status"] == "failed" for row in results)
    path = ROOT / "results.json"
    path.write_text(json.dumps({"passed": len(results) - failed, "failed": failed,
        "limitations": "Synthetic ranking/storage checks; not measured retrieval quality on real alerts or a model hallucination benchmark.",
        "checks": results}, indent=2), encoding="utf-8")
    print(f"\nSUMMARY: {len(results) - failed}/{len(results)} passed; {failed} failed.")
    print("Full results:", path)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
