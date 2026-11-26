"""Trusted query profiles. Each identity includes provider AND channel."""

from types import MappingProxyType

from cybertriage.domain.security_event import EventIdentity

SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _security(*ids: int) -> tuple[EventIdentity, ...]:
    return tuple(EventIdentity(SECURITY_PROVIDER, "Security", value) for value in ids)


FAMILY_IDENTITIES = MappingProxyType({
    "all": (),
    "authentication": _security(4624, 4625),
    "account_changes": _security(4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4741, 4742, 4743, 4767, 4781),
    "group_changes": _security(4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764),
    "process_activity": (*_security(4688, 4689), EventIdentity(SYSMON_PROVIDER, SYSMON_CHANNEL, 1),
                         EventIdentity(SYSMON_PROVIDER, SYSMON_CHANNEL, 5)),
})


def family_matches(family: str, event: EventIdentity | None) -> bool:
    return family == "all" or event in FAMILY_IDENTITIES[family]
