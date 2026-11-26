# Knowledge retrieval

Analysis uses `HybridKnowledgeRetriever` through the contextual retrieval port.
It combines semantic candidates from enabled Chroma collections with a global
BM25 lexical index, exact identifier matching, and explicit host-platform
metadata. It replaces source alternation in the default analysis composition.
The legacy text-only retrieval port remains supported by `AnalyzeAlert`.

## Ranking and evidence boundaries

The application builds retrieval context from the supplied event identity and
its local catalogue description. Known Windows Security, Sysmon and PowerShell
providers establish Windows host context; arbitrary log text does not determine
a platform. The inspection CLI can supply an explicit platform, but rejects a
platform that contradicts a known Windows provider.

The original query is augmented with the catalogue description when not already
present and with the known platform. Catalogue definitions remain separate,
first-class references in the report and are not replaced by semantic results.
Neither an event identity nor an ATT&CK reference proves malicious activity.

Each nonempty eligible collection contributes at most 20 semantic candidates.
BM25 contributes at most 20 lexical candidates from the latest eligible corpus.
Lexical ranking retains exact ATT&CK IDs and hexadecimal values, removes common
English stop words, and weights title terms twice relative to body terms.
BM25 uses k1=1.5 and b=0.75. Corpus document frequencies are computed globally
across active indexed passages, not separately on incomparable score scales.

Candidate fusion adds `1/(60+dense_rank)` and `1/(60+lexical_rank)` when those
signals exist. The best dense rank across collections is used, so copying a
chunk into another source does not create another vote. An explicitly requested
ATT&CK ID in a title or an exact Windows Security event document adds `3/61`.
Security event-document anchors require the matching Security provider/channel;
a numeric Sysmon ID cannot activate a Windows Security anchor.

The selected reference set initially allows one passage per source URL, then a
second passage where space remains. Normalized duplicate body excerpts do not
consume additional slots. Matching later chunks retain their own IDs and text;
the adapter does not replace them with a document's opening chunk. Entire
passages are selected within the reference budget rather than silently editing
text under an existing citation.

These are ranking heuristics, not calibrated confidence scores. Semantic-only
candidates can still be selected when they supply context missed by lexical
matching. The retriever does not claim that every returned passage is relevant,
that no relevant passage exists outside the bounded pools, or that report
hallucination has been eliminated. Real alert queries and relevance judgements
are required to measure recall, precision and report quality.

## Platform metadata and existing collections

MITRE documents retain the source's `x_mitre_platforms`; the Windows event
documentation adapter explicitly marks its documents as Windows. Chroma stores
the list in scalar JSON metadata alongside the existing source/revision/hash
fields. A passage explicitly limited to known host platforms that exclude the
incident's platform is filtered. Empty metadata and non-host platforms remain
eligible; compatibility is not guessed from a technique name or example text.

Existing collections remain readable, but missing platform metadata cannot
exclude an incompatible reference. Refresh the configured sources to populate
that metadata, then restart analysis processes. Ingestion updates metadata for
unchanged chunk IDs without supplying document text or embedding values to the
native Chroma update call. This preserves the original embeddings. New chunks
still follow the existing embedding path. Stored text that conflicts with an
existing chunk ID raises an error instead of being overwritten.

The refresh does not change source revision pins, chunking configuration, model
names or collection names. It does not delete old chunks or rewrite old reports.
Model or embedding-policy changes require a deliberately compatible collection;
metadata refresh is not an embedding migration.

## Snapshot lifecycle and resource limits

The lexical snapshot loads lazily and is cached for the lifetime of a retriever.
A lock publishes the corpus/index only after all sources have loaded correctly.
Query ranks, selection and provenance are invocation-local.

For each source/document identity, the snapshot selects the most recently
fetched revision, content hash and retrieval timestamp. This excludes old
revisions and older chunking layouts still stored in the collection. It is a
latest-fetched rule, not a guarantee of latest upstream publication. Conflicting
chunk identities, equal-time competing revisions and duplicate chunk positions
in the latest snapshot fail visibly.

Chroma snapshots are paginated and reject duplicate, malformed or incomplete
records and collection-count changes during reading. Semantic candidates must
match their captured collection and full snapshot metadata/text; later changes
require restarting analysis rather than mixing incompatible candidate states.
Count checks cannot detect every concurrent metadata-only update. Complete
ingestion before starting/restarting analysis; this is not an atomic publication
or online index-switching protocol. A failed partial ingestion must be repaired
before that corpus is used.

Limits are explicit:

- 10,000 passages and 32 MiB of serialized content per Chroma snapshot.
- 20,000 passages and 64 MiB across enabled collections.
- Two million lexical term/passage entries.
- 4,000 UTF-8 bytes in the original query and 256 distinct effective query terms.
- 4,000 characters per stored passage, 1–20 requested references, at most two
  per source URL, and 12,000 UTF-8 bytes of background reference text.
- 128 KiB of retrieval trace JSON.

Serialized-content limits do not describe total Python heap usage; lexical
postings and object overhead add memory. Source/snapshot/semantic failures remain
errors, not empty successful searches. Empty or entirely incompatible eligible
corpora can return no background references, with that condition visible in the
trace; an exact catalogue definition can still support the report.

## Provenance

Each result carries a query-local trace with policy version, corpus fingerprint,
original/effective query hashes, event/platform context, corpus/eligibility counts,
and each selected chunk's source revision, document hash, retrieval timestamp,
platform metadata, ranks, exact-match reasons and fusion score. This records
selection provenance, not externally signed integrity or source completeness.

`TriageResult.retrieval_trace_json` persists this trace with existing report JSON,
including worker reports and case-linked report history. No SQLite schema
change is required because reports already store structured result JSON.
Legacy retrieval ports leave the optional trace null; old reports remain readable.
The trace is not inserted into the model prompt as extra incident observations.

## Inspection and validation

The `retrieve` command emits selected references and trace without generating a
chat-model report. It uses the configured embedding model for semantic queries,
so Ollama must be available when eligible collections contain data. It does not
require Wazuh or the Indexer. Usage and refresh commands are in the README.

`python scripts/validate_retrieval.py` supplies 17 offline check groups with
in-memory source/store/model substitutes. They cover hybrid signal fusion,
explicit/unknown platform metadata, exact identifiers, source/provider boundaries,
chunk preservation, diversity, old snapshots, conflicts, source failures, input
and output limits, concurrent contexts, metadata-only refresh, and analysis
provenance/backward compatibility. Only validation reports are written under
ignored `data/validation/retrieval-*`. These checks have not yet been executed.

Controlled live web retrieval, freshness/TTL policy, source-specific web caches,
and a labelled real-query retrieval benchmark remain separate work. No incident
query is automatically sent to an internet search service by this feature.

## SDK references

- [Chroma collection get/update implementation](https://github.com/chroma-core/chroma/blob/main/chromadb/api/models/Collection.py)
- [Chroma update behavior](https://github.com/chroma-core/docs/blob/main/docs/usage-guide.md#updating-data-in-a-collection)
