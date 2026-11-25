from datetime import timedelta, timezone
from pathlib import Path

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from cybertriage.adapters.configuration.yaml_files import _read_yaml
from cybertriage.domain.triage_policy import GroupingRule, SuppressionRule, TriageSettings


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Suppression(_Model):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    source_instance: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=64)
    wazuh_rule_id: str = Field(min_length=1, max_length=64)
    fields: dict[str, str] = Field(min_length=2, max_length=8)
    # YAML's native timestamps are accepted; quoted strings are parsed explicitly below.
    starts_at: AwareDatetime
    expires_at: AwareDatetime
    max_level: int = Field(ge=0, le=11)
    reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def bounded_period(self):
        if not timedelta(0) < self.expires_at - self.starts_at <= timedelta(days=30):
            raise ValueError("Suppression rules must expire within 30 days of their start.")
        return self


class _Grouping(_Model):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    wazuh_rule_ids: list[str] = Field(default_factory=list, max_length=100)
    provider: str | None = None
    channel: str | None = None
    event_ids: list[int] = Field(default_factory=list, max_length=100)
    fields: list[str] = Field(min_length=2, max_length=6)
    window_seconds: int = Field(default=300, ge=1, le=3600)
    settle_seconds: int = Field(default=10, ge=0, le=60)
    max_members: int = Field(default=5, ge=2, le=5)

    @model_validator(mode="after")
    def scoped(self):
        if len(set(self.fields)) != len(self.fields):
            raise ValueError("Grouping field paths must be unique.")
        if not self.wazuh_rule_ids and not self.event_ids:
            raise ValueError("Grouping requires explicit rule IDs or event identities.")
        if self.event_ids and (not self.provider or not self.channel):
            raise ValueError("Grouping event IDs require provider and channel.")
        if not self.event_ids and (self.provider is not None or self.channel is not None):
            raise ValueError("Provider/channel require explicit grouping event IDs.")
        if any(type(value) is not int or not 0 <= value <= 65535 for value in self.event_ids):
            raise ValueError("Invalid grouping event ID.")
        return self


class _Settings(_Model):
    enabled: bool = True
    force_investigate_level: int = Field(default=12, ge=1, le=16)
    protected_windows_event_ids: list[int] = Field(
        default_factory=lambda: [1102, 4719, 4728, 4732, 4756], max_length=512,
    )
    suppression_rules: list[_Suppression] = Field(default_factory=list, max_length=100)
    grouping_rules: list[_Grouping] = Field(default_factory=list, max_length=100)


def _check_text(value: str, limit: int = 256) -> None:
    if not value or value != value.strip() or len(value) > limit or not value.isprintable():
        raise ValueError("Policy values require bounded printable text without surrounding whitespace.")


class YamlTriageConfiguration:
    def __init__(self, path: Path):
        self._path = path

    def load(self) -> TriageSettings:
        import re
        from datetime import datetime

        raw = _read_yaml(self._path)
        suppression_values = raw.get("suppression_rules", [])
        if not isinstance(suppression_values, list):
            raise ValueError("suppression_rules must be a list.")
        for rule in suppression_values:
            if isinstance(rule, dict):
                for name in ("starts_at", "expires_at"):
                    if isinstance(rule.get(name), str):
                        rule[name] = datetime.fromisoformat(rule[name])
        parsed = _Settings.model_validate(raw)
        ids = [rule.id for rule in [*parsed.suppression_rules, *parsed.grouping_rules]]
        if len(set(ids)) != len(ids):
            raise ValueError("Triage rule IDs must be unique.")
        if any(type(value) is not int or not 0 <= value <= 65535 for value in parsed.protected_windows_event_ids):
            raise ValueError("Invalid protected Windows event ID.")
        for rule in [*parsed.suppression_rules, *parsed.grouping_rules]:
            for key in rule.fields:
                if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*", key) or len(key) > 128:
                    raise ValueError("Invalid decoded-data field path.")
            if isinstance(rule, _Suppression):
                for value in (rule.source_instance, rule.agent_id, rule.wazuh_rule_id, *rule.fields.values()):
                    _check_text(value)
                _check_text(rule.reason, 1000)
                if rule.max_level >= parsed.force_investigate_level:
                    raise ValueError("Suppression max_level must be below the severity override.")
            else:
                for value in (*rule.wazuh_rule_ids, *rule.fields):
                    _check_text(value)
                for value in (rule.provider, rule.channel):
                    if value is not None:
                        _check_text(value)
        return TriageSettings(
            enabled=parsed.enabled,
            force_investigate_level=parsed.force_investigate_level,
            protected_windows_event_ids=tuple(parsed.protected_windows_event_ids),
            suppression_rules=tuple(SuppressionRule(
                rule.id, rule.source_instance, rule.agent_id, rule.wazuh_rule_id,
                tuple(sorted(rule.fields.items())), rule.starts_at.astimezone(timezone.utc),
                rule.expires_at.astimezone(timezone.utc), rule.max_level, rule.reason,
            ) for rule in parsed.suppression_rules),
            grouping_rules=tuple(GroupingRule(
                rule.id, tuple(rule.wazuh_rule_ids), rule.provider, rule.channel,
                tuple(rule.event_ids), tuple(rule.fields), rule.window_seconds,
                rule.settle_seconds, rule.max_members,
            ) for rule in parsed.grouping_rules),
        )
