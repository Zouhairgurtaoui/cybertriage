"""Explicit field projections and exact-match paths for the Wazuh 4.x alert shape."""

from ipaddress import ip_address

ACCOUNT_PAIRS = (
    ("data.win.eventdata.targetUserName", "data.win.eventdata.targetDomainName"),
    ("data.win.eventdata.subjectUserName", "data.win.eventdata.subjectDomainName"),
)
ACCOUNT_JOINED = ("data.win.eventdata.user", "data.win.eventdata.sourceUser", "data.win.eventdata.targetUser")
SOURCE_IP_FIELDS = ("data.srcip", "data.win.eventdata.ipAddress", "data.win.eventdata.sourceIp")
PROCESS_GUID_FIELDS = ("data.win.eventdata.processGuid", "data.win.eventdata.parentProcessGuid",
                       "data.win.eventdata.sourceProcessGUID", "data.win.eventdata.targetProcessGUID")
LOGON_ID_FIELDS = ("data.win.eventdata.targetLogonId", "data.win.eventdata.subjectLogonId", "data.win.eventdata.logonId")
DETAIL_FIELDS = (
    "data.win.system.eventRecordID", "data.win.system.systemTime", "data.win.system.computer",
    *(path for pair in ACCOUNT_PAIRS for path in pair),
    "data.win.eventdata.memberName", "data.win.eventdata.memberSid",
    "data.win.eventdata.targetSid", "data.win.eventdata.subjectUserSid",
    *SOURCE_IP_FIELDS, "data.win.eventdata.destinationIp", "data.win.eventdata.destinationPort",
    "data.win.eventdata.logonType", *LOGON_ID_FIELDS,
    "data.win.eventdata.status", "data.win.eventdata.subStatus", "data.win.eventdata.failureReason",
    *PROCESS_GUID_FIELDS, "data.win.eventdata.image", "data.win.eventdata.newProcessName",
    "data.win.eventdata.parentImage", "data.win.eventdata.processName",
    "data.win.eventdata.commandLine", "data.win.eventdata.parentCommandLine",
    "data.win.eventdata.processId", "data.win.eventdata.newProcessId", "data.win.eventdata.parentProcessId",
    *ACCOUNT_JOINED, "data.dstuser", "data.srcuser", "decoder.name", "location", "rule.description",
)
SOURCE_FIELDS = (
    "id", "timestamp", "manager.name", "agent.id", "agent.name", "rule.id", "rule.level",
    "data.win.system.providerName", "data.win.system.channel", "data.win.system.eventID",
    *DETAIL_FIELDS,
)


def field_at(value: object, path: str) -> object:
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def canonical_ip(value: str) -> str:
    parsed = ip_address(value)
    return str(getattr(parsed, "ipv4_mapped", None) or parsed)


def ip_terms(value: str) -> list[str]:
    parsed = ip_address(canonical_ip(value))
    terms = [value, str(parsed), parsed.exploded]
    if parsed.version == 4:
        mapped = ip_address(f"::ffff:{parsed}")
        terms.extend((f"::ffff:{parsed}", str(mapped), mapped.exploded))
    return list(dict.fromkeys(terms))
