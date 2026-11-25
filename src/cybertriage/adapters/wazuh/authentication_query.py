from cybertriage.domain.investigation import AuthenticationSearchRequest
from collections.abc import Mapping, Sequence
from typing import TypeAlias


JsonValue: TypeAlias = (
    str
    | int
    | float
    | bool
    | None
    | Sequence["JsonValue"]
    | Mapping[str, "JsonValue"]
)


SOURCE_FIELDS = (
    "id",
    "timestamp",
    "manager.name",
    "agent.id",
    "agent.name",
    "data.win.system.providerName",
    "data.win.system.channel",
    "data.win.system.eventID",
    "data.win.system.eventRecordID",
    "data.win.system.computer",
    "data.win.eventdata.targetUserName",
    "data.win.eventdata.targetDomainName",
    "data.win.eventdata.ipAddress",
    "data.win.eventdata.logonType",
    "data.win.eventdata.targetLogonId",
)


def build_authentication_query(
    request: AuthenticationSearchRequest,
) -> dict[str, JsonValue]:
    return {
        # Fetch one extra event to detect omitted results.
        "size": request.limit + 1,
        "track_total_hits": False,
        "timeout": "5s",
        "_source": list(SOURCE_FIELDS),
        "sort": [
            {"timestamp": {"order": "asc"}},
        ],
        "query": {
            "bool": {
                "filter": [
                    {
                        "term": {
                            "data.win.system.providerName":
                                "Microsoft-Windows-Security-Auditing"
                        }
                    },
                    {
                        "term": {
                            "data.win.system.channel": "Security"
                        }
                    },
                    {
                        "terms": {
                            "data.win.system.eventID": ["4624", "4625"]
                        }
                    },
                    {
                        "term": {
                            "data.win.eventdata.targetUserName":
                                request.account_name
                        }
                    },
                    {
                        "term": {
                            "data.win.eventdata.targetDomainName":
                                request.account_domain
                        }
                    },
                    {
                        "range": {
                            "timestamp": {
                                "gte": request.start.isoformat(),
                                "lt": request.end.isoformat(),
                            }
                        }
                    },
                ]
            }
        },
    }