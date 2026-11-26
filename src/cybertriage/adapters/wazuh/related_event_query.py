from cybertriage.adapters.wazuh.json_types import JsonValue
from cybertriage.adapters.wazuh.related_event_fields import (
    ACCOUNT_JOINED, ACCOUNT_PAIRS, LOGON_ID_FIELDS, PROCESS_GUID_FIELDS,
    SOURCE_FIELDS, SOURCE_IP_FIELDS, ip_terms,
)
from cybertriage.application.policies.event_families import FAMILY_IDENTITIES
from cybertriage.domain.related_events import RelatedEventSearchRequest


def any_terms(paths: tuple[str, ...], values: list[str]) -> dict[str, JsonValue]:
    alternatives: list[JsonValue] = [{"terms": {path: values}} for path in paths]
    return {"bool": {"should": alternatives, "minimum_should_match": 1}}


def build_related_event_query(request: RelatedEventSearchRequest) -> dict[str, JsonValue]:
    filters: list[JsonValue] = [
        {"term": {"manager.name": request.source_instance}},
        {"term": {"agent.id": request.agent_id}},
        {"range": {"timestamp": {"gte": request.start.isoformat(), "lt": request.end.isoformat()}}},
    ]
    identities = FAMILY_IDENTITIES[request.family]
    if identities:
        alternatives: list[JsonValue] = []
        for event in identities:
            alternatives.append({"bool": {"filter": [
                {"term": {"data.win.system.providerName": event.provider}},
                {"term": {"data.win.system.channel": event.channel}},
                {"term": {"data.win.system.eventID": str(event.event_id)}},
            ]}})
        filters.append({"bool": {"should": alternatives, "minimum_should_match": 1}})
    if request.account_name is not None and request.account_domain is not None:
        account_filters: list[JsonValue] = [
            {"bool": {"filter": [{"term": {name: request.account_name}}, {"term": {domain: request.account_domain}}]}}
            for name, domain in ACCOUNT_PAIRS
        ]
        account_filters.extend({"term": {path: f"{request.account_domain}\\{request.account_name}"}} for path in ACCOUNT_JOINED)
        filters.append({"bool": {"should": account_filters, "minimum_should_match": 1}})
    if request.source_ip is not None:
        filters.append(any_terms(SOURCE_IP_FIELDS, ip_terms(request.source_ip)))
    if request.process_guid is not None:
        filters.append(any_terms(PROCESS_GUID_FIELDS, [request.process_guid]))
    if request.logon_id is not None:
        filters.append(any_terms(LOGON_ID_FIELDS, [request.logon_id]))
    return {"size": request.limit + 1, "track_total_hits": False, "timeout": "5s",
            "_source": list(SOURCE_FIELDS), "sort": [{"timestamp": {"order": "asc"}}],
            "query": {"bool": {"filter": filters}}}
