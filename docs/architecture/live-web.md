# Controlled live knowledge retrieval

Live retrieval augments the existing local hybrid retriever with public
Microsoft Learn event documentation and MITRE ATT&CK technique descriptions.
It resolves technical identifiers to fixed vendor routes. Additional providers
and search-engine discovery are future extensions of the source interfaces.

## Composition and source policy

`LiveWebKnowledgeRetriever` implements the contextual retrieval port and wraps
the local retriever. `LiveDocumentReader` coordinates a document cache, HTTPS
fetcher and HTML parser through application ports. Route planning and URL
approval are separate application policies. The composition root supplies the
adapters and validated settings from `config/sources.yaml`.

Local retrieval runs first. A local corpus failure remains an error; a web
lookup cannot conceal a broken local index. Eligible public targets are then
derived from:

- A supplied Windows Security event identity, with the exact Security provider
  and channel. Numeric IDs from other providers do not become Security lookups.
- Explicit ATT&CK technique IDs in the focused query, followed by technique IDs
  in selected local reference titles when target capacity remains.

Only syntactically constrained identifiers enter generated request paths.
Incident text, account names, source IPs, timestamps and the original query are
not submitted to an internet search API. Requests carry ordinary public HTTP
cache validators when available. No Indexer credentials, ingestion tokens,
cookies or application authentication headers are attached.

Microsoft routes try the established event-document path, its current auditing
counterpart, then the official audit catalogue. A page must contain a validated
event heading, labelled event reference or matching catalogue row. Malformed
200 responses can fall through to another approved route. Missing direct pages
therefore do not restrict retrieval to a small hardcoded event list.

MITRE routes use `/techniques/Txxxx/` or `/techniques/Txxxx/xxx/`. Parsers confirm
the labelled technique ID, extract description paragraphs and retain explicit
platform metadata. Semantic HTML fallbacks support changed article containers;
an unrecognized or insufficient article remains a lookup error.

## HTTPS boundary

The live fetcher uses a direct verified HTTPS connection to the exact approved
vendor host. Redirects remain on that same host and inside the fixed route
allowlist, with at most two redirects. Credentials, nonstandard ports, queries,
fragments, encoded paths and traversal routes are rejected.

DNS answers are checked for public destinations before connecting. Mixed
public/private answers, loopback, link-local, shared/private ranges, mapped
private addresses and IPv6 transition destinations are rejected. The connection
pins the selected IP while retaining the vendor hostname for TLS verification
and SNI, preventing a second hostname resolution at connection time. At most
two validated addresses are tried. System/environment HTTP proxies are not used.

The client requests identity-encoded HTML, verifies content type and response
framing, and caps each body at 2 MiB. Compressed, incomplete, ambiguous or
oversized responses fail. HTML is parsed as data; scripts, forms, frames,
navigation and page actions are removed, and page links/assets are not followed.
An extracted article is capped at 150,000 characters. Source origin validation
and content hashes do not certify the publisher's factual accuracy.

The default retrieval budget is two identifier targets and six HTTP attempts.
Every attempt, including redirects/address retries, consumes that shared budget.
An advisory 30-second deadline bounds request scheduling and body reads;
connect and read timeouts are also limited. OS DNS resolution and a blocking
socket operation can extend elapsed time beyond the advisory deadline. These
controls are not a hard process-level wall-clock cancellation guarantee.

## Cache lifecycle

Public article snapshots use a separate SQLite cache under ignored `data/cache`.
Live requests do not mutate the already loaded Chroma corpus. Static source
ingestion and embedding policy remain unchanged; promoting web snapshots into
the static index would require an explicit publication/ingestion workflow.

The cache key includes the parser policy, vendor and identifier. Each entry
retains its canonical URL, cleaned source document, content revision and hash,
original fetch time, last validation time, expiry, ETag and Last-Modified values.
Payload hashes detect accidental corruption; this is not a tamper-proof store
against a database administrator who can rewrite files and hashes.

Fresh entries avoid HTTP requests. Expired entries can send conditional headers;
a valid 304 extends validation/expiry without changing the original fetch time.
Only a 304 for the cached resource can reuse its document. Redirects drop the
original resource's validators. A missing page is cached only after approved
fallback routes have all returned 404/410; transport and parser failures are
not converted into successful empty knowledge.

Refreshes hold a 60-second transactional lease. Duplicate refreshes can return
explicitly labelled stale context within policy, or an in-progress result.
Transient failures and cache-publication failures retain the lease until expiry
as a short backoff, reducing repeated upstream requests during outages. Old
owners cannot overwrite or release a newer claim.

Default policy:

| Setting | Default |
| --- | --- |
| Positive TTL | 24 hours |
| Missing-page TTL | 15 minutes |
| Maximum stale interval after expiry | 7 days |
| Stale on transient failure | Enabled, with an explicit stale label |
| Maximum identifier targets | 2 |
| Maximum HTTP attempts | 6 |

Policy/TLS/parser failures do not serve an expired document as a freshly
validated success. A transient failure can use a previously validated document
only within the configured stale interval. Expired documents beyond that limit
are omitted. Cache corruption or unavailable cache storage produces a visible
lookup error and leaves local retrieval available. Warnings/logs and report
traces expose degraded or stale outcomes.

Entries are limited to 1 MiB each, 512 entries and 64 MiB of retained serialized
payload. Oldest validated entries are evicted transactionally when necessary.
Those are logical payload limits; SQLite pages, journals and free space can make
physical disk usage larger. Cache eviction does not delete saved report excerpts
or report provenance. Refresh claims are also bounded. Existing non-cache
databases are rejected as cache paths rather than receiving unrelated tables.

## Reference selection and provenance

Validated articles are split using the configured chunking policy. A pre-split
input bound based on chunk stride and a 256-chunk output limit constrain work
for small chunks or large overlaps. One matching excerpt per live document is
selected with lexical ranking. Oversized inputs/metadata are recorded as
budget exclusions rather than silently editing text under a citation ID.

Fresh exact-identifier web context precedes available local context. Permitted
stale web context follows local references. When web material is available,
the merged set permits one excerpt per URL and stays within k and the existing
12,000-byte reference-text budget. If no usable web material exists, the local
reference set is preserved. Fresh explicit incompatible-platform metadata can
exclude a matching obsolete local URL; stale metadata cannot make that override.

Live references retain their own chunk IDs and unmodified excerpt text, plus
separate application provenance: source/identifier, lookup status, stale flag,
fetch/validation/expiry dates, content hash, revision and platform metadata.
Both report paths show this metadata in the reference context, separately from
incident observations. Freshness describes retrieval/validation with the vendor;
it does not guarantee that upstream documentation reflects every recent change.

Reports persist final selected IDs and provenance alongside public lookup
statuses, request counts, approved route candidates, failures and platform
exclusions. The local ranking trace remains nested as `local_candidate_trace`.
Model reports remain provisional; public guidance does not establish attacker
identity, compromise, incident relationships or response approval.

## Configuration and offline operation

`live_web` is an optional validated section of `sources.yaml`. The distributed
configuration enables both vendors; older files without the section keep live
retrieval disabled. Unknown fields, invalid types/limits, unsupported vendors
and unsafe cache paths are rejected. Vendor-level source enablement is also
honored. The cache path must remain beneath the project's data directory.

`--offline-knowledge` is available on `retrieve`, `analyze`, `analyze-stored` and
`worker`. It bypasses both live refresh and web-cache augmentation, using the
local Chroma corpus. It does not disable Indexer investigation tools or remove
the local embedding/chat-model requirements of the selected command.

Restart existing workers to load code and policy changes. Usage is in the README.
No additional model, dependency, browser installation or paid search key is
required for this identifier-based capability.

## Validation

`python scripts/validate_live_web.py` provides 22 offline check groups using
mock HTTP/DNS, synthetic HTML and fresh isolated cache databases under ignored
`data/validation/live-web-*`. Coverage includes route/privacy boundaries, DNS
and pinned TLS, HTTP limits, article identity/layouts, TTL/304/negative caching,
stale limits and backoff, corruption, lease ownership, quota rollback, reference
selection, platform overrides and configuration compatibility.

These checks have been added but not executed. Live vendor HTML/redirect/TLS
compatibility, network workload, retrieval relevance and model interpretation
remain separate validation. Syntax/import/configuration/help checks do not
establish those operational or semantic properties.

## Source references

- [Microsoft event documentation example](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4725)
- [Microsoft audit catalogue](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [MITRE ATT&CK technique example](https://attack.mitre.org/techniques/T1098/007/)
