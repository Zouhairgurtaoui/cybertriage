"""Validate reported-field relationships without asserting an attack chain."""

import json
from datetime import timezone
from ipaddress import ip_address

from cybertriage.domain.case import CaseAlertEvidence, CaseError

OBSERVED_PREDICATES = frozenset({
    "shares_host", "shares_account_fields", "shares_source_ip", "shares_session",
    "precedes_by_reported_time",
})


def _field(data: object, path: str) -> str | None:
    value = data
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value if isinstance(value, str) and value.strip() not in {"", "-"} else None


class ObservedRelationshipPolicy:
    def prove(self, predicate: str, left: CaseAlertEvidence, right: CaseAlertEvidence) -> str:
        if predicate not in OBSERVED_PREDICATES:
            raise CaseError("Unsupported observed predicate.")
        a, b = left.alert, right.alert
        ad, bd = json.loads(a.decoded_data_json), json.loads(b.decoded_data_json)
        same_manager = a.source_instance == b.source_instance
        same_host = same_manager and a.agent_id == b.agent_id
        match: dict[str, object] | None = None
        limitation = "A shared reported field does not establish a common person, attacker, or causal link."
        if predicate == "shares_host" and same_host:
            match = {"source_instance": a.source_instance, "agent_id": a.agent_id}
        elif predicate == "precedes_by_reported_time" and a.timestamp < b.timestamp:
            match = {"source.timestamp": a.timestamp.astimezone(timezone.utc).isoformat(),
                     "target.timestamp": b.timestamp.astimezone(timezone.utc).isoformat()}
            limitation = "Reported timestamp order only; clock accuracy and causation are not established."
        elif predicate == "shares_account_fields" and same_manager:
            def identities(data: object) -> list[tuple[str, str, str, str]]:
                values = []
                for role in ("target", "subject"):
                    name_path = f"win.eventdata.{role}UserName"
                    domain_path = f"win.eventdata.{role}DomainName"
                    name, domain = _field(data, name_path), _field(data, domain_path)
                    if name and domain:
                        values.append((name_path, name, domain_path, domain))
                return values
            for x in identities(ad):
                for y in identities(bd):
                    if x[1].casefold() == y[1].casefold() and x[3].casefold() == y[3].casefold():
                        match = {"source_fields": {x[0]: x[1], x[2]: x[3]},
                                 "target_fields": {y[0]: y[1], y[2]: y[3]},
                                 "source_instance": a.source_instance}
                        break
            if match is None and same_host:
                x, y = _field(ad, "dstuser"), _field(bd, "dstuser")
                if x and x == y:
                    match = {"source.dstuser": x, "target.dstuser": y,
                             "agent_id": a.agent_id, "source_instance": a.source_instance}
        elif predicate == "shares_source_ip" and same_manager:
            for ap in ("srcip", "win.eventdata.ipAddress"):
                for bp in ("srcip", "win.eventdata.ipAddress"):
                    try:
                        av, bv = _field(ad, ap), _field(bd, bp)
                        if av is None or bv is None:
                            continue
                        x, y = ip_address(av), ip_address(bv)
                        x = getattr(x, "ipv4_mapped", None) or x
                        y = getattr(y, "ipv4_mapped", None) or y
                    except ValueError:
                        continue
                    if x == y and not x.is_unspecified and ((not x.is_loopback and not x.is_link_local) or same_host):
                        match = {"source_field": ap, "target_field": bp, "ip": str(x),
                                 "source_instance": a.source_instance, "host_scoped": x.is_loopback or x.is_link_local}
        elif predicate == "shares_session" and same_host:
            def session(evidence: CaseAlertEvidence, data: object) -> tuple[str, str] | None:
                event = evidence.alert.event
                if not event or event.provider != "Microsoft-Windows-Security-Auditing" or event.channel != "Security" or event.event_id == 4625:
                    return None
                path = "win.eventdata.targetLogonId" if event.event_id == 4624 else "win.eventdata.subjectLogonId"
                raw = _field(data, path)
                try:
                    number = int(raw, 16) if raw and raw.lower().startswith("0x") else 0
                except ValueError:
                    return None
                return (path, hex(number)) if number > 0 else None
            x, y = session(left, ad), session(right, bd)
            if x and y and x[1] == y[1]:
                match = {"source_field": x[0], "target_field": y[0], "logon_id": x[1],
                         "source_instance": a.source_instance, "agent_id": a.agent_id}
                limitation = "Same reported host-scoped logon ID; IDs can be reused after reboot. This is not proof of a common attacker."
        if match is None:
            raise CaseError("Stored evidence does not establish this observed relationship.")
        return json.dumps({"version": 1, "predicate": predicate, "match": match,
                           "source_payload_sha256": left.payload_hash,
                           "target_payload_sha256": right.payload_hash,
                           "limitation": limitation}, ensure_ascii=False, allow_nan=False)
