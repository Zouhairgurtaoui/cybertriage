import logging
import re
from hashlib import sha256

from bs4 import BeautifulSoup

from cybertriage.domain.security_event import SecurityEventDefinition


MICROSOFT_AUDIT_URL = (
    "https://learn.microsoft.com/en-us/windows-server/identity/"
    "ad-ds/plan/security-best-practices/"
    "advanced-audit-policy-configuration"
)

PROVIDER = "Microsoft-Windows-Security-Auditing"
CHANNEL = "Security"

logger = logging.getLogger(__name__)


class MicrosoftSecurityEventCatalog:
    def __init__(
        self,
        definitions: list[SecurityEventDefinition],
    ):
        self._definitions = {}

        for definition in definitions:
            key = (
                definition.provider,
                definition.channel,
                definition.event_id,
            )

            if key in self._definitions:
                raise ValueError(f"Duplicate event definition: {key}")

            self._definitions[key] = definition

    def definitions(self) -> list[SecurityEventDefinition]:
        return sorted(
            self._definitions.values(),
            key=lambda definition: (
                definition.provider,
                definition.channel,
                definition.event_id,
            ),
        )

    def lookup(
        self,
        provider: str,
        channel: str,
        event_id: int,
    ) -> SecurityEventDefinition | None:
        return self._definitions.get((provider, channel, event_id))

    def __len__(self) -> int:
        return len(self._definitions)

    @classmethod
    def from_html(
        cls,
        html: bytes,
        source_url: str = MICROSOFT_AUDIT_URL,
    ) -> "MicrosoftSecurityEventCatalog":
        soup = BeautifulSoup(html, "html.parser")
        main = soup.select_one("main")

        if main is None:
            raise ValueError("Microsoft documentation has no main content.")

        heading = main.find("h1")

        if (
            heading is None
            or heading.get_text(" ", strip=True)
            != "Advanced Audit Policy Configuration"
        ):
            raise ValueError("Unexpected Microsoft documentation page.")

        descriptions: dict[int, str] = {}
        conflicted_ids: set[int] = set()

        for table in main.find_all("table"):
            headers = [
                " ".join(cell.get_text(" ", strip=True).lower().split())
                for cell in table.select("thead th")
            ]

            if headers != ["event id", "event message"]:
                continue

            for row in table.select("tbody tr"):
                cells = row.find_all("td", recursive=False)

                if len(cells) != 2:
                    raise ValueError("Unexpected event table row structure.")

                raw_id = cells[0].get_text(" ", strip=True)
                description = cells[1].get_text(" ", strip=True)

                if not re.fullmatch(r"[0-9]{4}", raw_id):
                    raise ValueError(f"Unexpected event ID: {raw_id!r}")

                if not description:
                    raise ValueError(f"Empty definition for event {raw_id}.")

                event_id = int(raw_id)

                if event_id in conflicted_ids:
                    continue

                previous = descriptions.get(event_id)

                if previous is not None and previous != description:
                    descriptions.pop(event_id)
                    conflicted_ids.add(event_id)

                    logger.warning(
                        "Excluded event %d: source contains "
                        "conflicting descriptions.",
                        event_id,
                    )
                    continue

                descriptions[event_id] = description

        if not descriptions:
            raise ValueError("No event definitions were extracted.")

        # Fingerprint the extracted data, excluding HTML layout changes.
        canonical = "\n".join(
            f"{event_id}\t{description}"
            for event_id, description in sorted(descriptions.items())
        )
        revision = "sha256:" + sha256(
            canonical.encode("utf-8")
        ).hexdigest()

        definitions = [
            SecurityEventDefinition(
                provider=PROVIDER,
                channel=CHANNEL,
                event_id=event_id,
                description=description,
                source_url=source_url,
                source_revision=revision,
            )
            for event_id, description in sorted(descriptions.items())
        ]

        return cls(definitions)
