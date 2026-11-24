import json
import re
from datetime import datetime, timezone

import requests

from cybertriage.domain.knowledge import KnowledgeDocument


MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024


class MitreSource:
    def __init__(self, revision: str):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("MITRE revision must be a full Git commit SHA.")

        self.revision = revision

    def fetch(self) -> list[KnowledgeDocument]:
        url = (
            "https://raw.githubusercontent.com/"
            f"mitre-attack/attack-stix-data/{self.revision}/"
            "enterprise-attack/enterprise-attack.json"
        )

        with requests.get(
            url,
            headers={"User-Agent": "CyberTriage/0.1"},
            timeout=(10, 30),
            stream=True,
            allow_redirects=False,
        ) as response:
            response.raise_for_status()

            if response.status_code != 200:
                raise RuntimeError(
                    f"Unexpected MITRE response: {response.status_code}"
                )

            content = bytearray()

            for block in response.iter_content(chunk_size=64 * 1024):
                if len(content) + len(block) > MAX_DOWNLOAD_BYTES:
                    raise ValueError("MITRE download exceeds the size limit.")

                content.extend(block)

        bundle = json.loads(content)
        retrieved_at = datetime.now(timezone.utc)

        return self._parse_bundle(bundle, retrieved_at)

    def _parse_bundle(
        self,
        bundle: dict,
        retrieved_at: datetime,
    ) -> list[KnowledgeDocument]:
        if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
            raise ValueError("Expected a STIX bundle.")

        objects = bundle.get("objects")

        if not isinstance(objects, list):
            raise ValueError("STIX bundle must contain an objects list.")

        documents = []

        for item in objects:
            if not isinstance(item, dict):
                raise ValueError("Invalid object in STIX bundle.")

            if item.get("type") != "attack-pattern":
                continue

            if item.get("revoked") or item.get("x_mitre_deprecated"):
                continue

            reference = next(
                (
                    ref
                    for ref in item.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id")
                    and ref.get("url")
                ),
                None,
            )

            if reference is None:
                raise ValueError(
                    f"Technique lacks its ATT&CK reference: {item.get('id')}"
                )

            documents.append(
                KnowledgeDocument(
                    document_id=f"mitre_attack:{item['id']}",
                    source_name="mitre_attack",
                    title=f"{reference['external_id']}: {item['name']}",
                    text=item["description"],
                    source_url=reference["url"],
                    source_revision=self.revision,
                    retrieved_at=retrieved_at,
                )
            )

        return documents