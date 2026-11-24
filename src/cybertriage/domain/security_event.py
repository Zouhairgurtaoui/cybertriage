from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityEventDefinition:
    provider: str
    channel: str
    event_id: int
    description: str
    source_url: str
    source_revision: str


@dataclass(frozen=True)
class EventIdentity:
    provider: str
    channel: str
    event_id: int

    def __post_init__(self):
        if not self.provider.strip() or not self.channel.strip():
            raise ValueError("Event provider and channel must not be empty.")

        if type(self.event_id) is not int or not 0 <= self.event_id <= 65535:
            raise ValueError("Event ID must be an integer from 0 to 65535.")