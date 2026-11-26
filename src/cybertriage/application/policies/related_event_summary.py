"""Compute search facts independently of model interpretations and SDKs."""

from collections import Counter
from dataclasses import asdict

from cybertriage.application.policies.event_families import FAMILY_IDENTITIES
from cybertriage.application.ports.event_catalog import SecurityEventCatalog
from cybertriage.domain.related_events import RelatedEventSearchResult


def related_event_summary(result: RelatedEventSearchResult, catalog: SecurityEventCatalog | None = None) -> dict[str, object]:
    counts = Counter((row.event.provider, row.event.channel, row.event.event_id) if row.event else (None, None, None)
                     for row in result.events)
    identities = sorted((key for key in counts if key[0] is not None), key=str)
    definitions = []
    if catalog is not None:
        for event in {row.event for row in result.events if row.event is not None}:
            definition = catalog.lookup(event.provider, event.channel, event.event_id)
            if definition is not None:
                definitions.append(asdict(definition))
        definitions.sort(key=lambda row: (row["provider"], row["channel"], row["event_id"]))
    return {
        "timestamp_basis": "Wazuh alert timestamp; reported Windows systemTime, when present, is a separate field.",
        "start_inclusive": result.request.start.isoformat(), "end_exclusive": result.request.end.isoformat(),
        "duration_seconds": (result.request.end - result.request.start).total_seconds(),
        "filters": asdict(result.request),
        "family_event_identities": [asdict(event) for event in FAMILY_IDENTITIES[result.request.family]],
        "family_filter_note": "all imposes no provider/channel/event-ID filter; other families are finite listed profiles.",
        "returned_event_count": len(result.events), "has_more": result.has_more,
        "returned_event_counts": [{"provider": key[0], "channel": key[1], "event_id": key[2], "count": counts[key]} for key in identities],
        "untyped_alert_count": counts[(None, None, None)], "event_definitions": definitions,
        "projection_truncated": any(row.fields_omitted or any(item.truncated for item in row.fields) for row in result.events),
        "coverage": result.coverage,
        "interpretation": "Candidate context only. Shared fields and timing do not establish a common actor, causation or compromise. Undefined event IDs, status codes and resource tokens remain unresolved.",
    }
