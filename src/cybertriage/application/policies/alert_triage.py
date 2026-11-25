import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from cybertriage.domain.alert import SecurityAlert
from cybertriage.domain.triage_policy import GroupingCandidate, TriagePlan, TriageSettings


def decoded_field(data: object, path: str) -> str | None:
    current = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    if (not isinstance(current, str) or current in ("", "-")
            or len(current) > 256 or not current.isprintable()):
        return None
    return current


class AlertTriagePolicy:
    """Pure, explicit matching; an unknown alert remains eligible for analysis."""

    def __init__(self, settings: TriageSettings):
        self._settings = settings
        self._snapshot = json.dumps(asdict(settings), sort_keys=True,
                                    separators=(",", ":"), default=self._date)
        self.revision = sha256(self._snapshot.encode("utf-8")).hexdigest()

    @staticmethod
    def _date(value: object) -> str:
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat()
        raise TypeError("Unsupported policy value.")

    def decide(self, alert: SecurityAlert, *, at: datetime) -> TriagePlan:
        if at.utcoffset() is None or alert.timestamp.utcoffset() is None:
            raise ValueError("Triage timestamps must include a timezone.")

        def plan(action, reason, rule_id=None, grouping=None):
            return TriagePlan(action, reason, rule_id, self.revision, self._snapshot, grouping)

        settings = self._settings
        if not settings.enabled:
            return plan("investigate", "policy_disabled")
        if alert.rule_level >= settings.force_investigate_level:
            return plan("investigate", "severity_override")
        if (alert.event is not None
                and alert.event.provider == "Microsoft-Windows-Security-Auditing"
                and alert.event.channel == "Security"
                and alert.event.event_id in settings.protected_windows_event_ids):
            return plan("investigate", "protected_event_override")

        data = json.loads(alert.decoded_data_json)
        for rule in settings.suppression_rules:
            if (rule.source_instance == alert.source_instance
                    and rule.agent_id == alert.agent_id
                    and rule.wazuh_rule_id == alert.rule_id
                    and alert.rule_level <= rule.max_level
                    and rule.starts_at <= at < rule.expires_at
                    and rule.starts_at <= alert.timestamp < rule.expires_at
                    and all(decoded_field(data, key) == value for key, value in rule.fields)):
                return plan("suppress", rule.reason, rule.rule_id)

        for rule in settings.grouping_rules:
            if rule.wazuh_rule_ids and alert.rule_id not in rule.wazuh_rule_ids:
                continue
            if rule.event_ids and (alert.event is None
                    or alert.event.provider != rule.provider
                    or alert.event.channel != rule.channel
                    or alert.event.event_id not in rule.event_ids):
                continue
            values = [decoded_field(data, key) for key in rule.fields]
            if any(value is None for value in values):
                continue
            seconds = int(alert.timestamp.timestamp())
            start = datetime.fromtimestamp(seconds - seconds % rule.window_seconds, timezone.utc)
            identity = [self.revision, rule.rule_id, alert.source_instance,
                        alert.agent_id, alert.rule_id,
                        asdict(alert.event) if alert.event else None,
                        start.isoformat(), list(zip(rule.fields, values))]
            fingerprint = sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()
            candidate = GroupingCandidate(
                fingerprint, start.isoformat(),
                (start + timedelta(seconds=rule.window_seconds)).isoformat(),
                rule.settle_seconds, rule.max_members,
            )
            return plan("investigate", "candidate_group", rule.rule_id, candidate)
        return plan("investigate", "no_suppression_match")
