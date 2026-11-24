from datetime import datetime, timezone
from hashlib import sha256

import requests
from bs4 import BeautifulSoup

from cybertriage.domain.knowledge import KnowledgeDocument
from cybertriage.domain.configuration import KnowledgePage
from cybertriage.adapters.knowledge.sources.microsoft_http import (
    download_microsoft_html,
)


class MicrosoftEventSource:
    def __init__(self, base_url: str, pages: tuple[KnowledgePage, ...]):
        if not pages:
            raise ValueError("At least one Microsoft documentation page is required.")
        self._base_url = base_url.rstrip("/")
        self._pages = pages

    def fetch(self) -> list[KnowledgeDocument]:
        documents = []

        with requests.Session() as session:
            session.headers.update({
                "User-Agent": "CyberTriage/0.1",
                "Accept": "text/html",
            })

            for page in self._pages:
                documents.append(
                    self._fetch_page(
                        session,
                        page.slug,
                        page.expected_heading,
                    )
                )

        return documents

    def _fetch_page(
        self,
        session: requests.Session,
        page_slug: str,
        expected_heading: str,
    ) -> KnowledgeDocument:
        url = f"{self._base_url}/{page_slug}"
        content = download_microsoft_html(session, url)

        soup = BeautifulSoup(content, "html.parser")

        heading = soup.select_one("main h1")

        article_candidates = [
            element
            for element in soup.select("main .content")
            if element.find(["p", "table", "ul", "ol", "pre"]) is not None
        ]

        if heading is None or len(article_candidates) != 1:
            raise ValueError(
                f"Article structure not recognised for page {page_slug}: "
                f"found {len(article_candidates)} article candidates."
            )

        article = article_candidates[0]
        title = heading.get_text(" ", strip=True)

        if not title.startswith(expected_heading):
            raise ValueError(
                f"Unexpected article title for {page_slug}: {title}"
            )

        for element in article.select(
            "script, style, nav, form, button, .metadata"
        ):
            element.decompose()

        text = article.get_text("\n", strip=True)

        if len(text) < 200:
            raise ValueError(
                f"Insufficient article content for page {page_slug}."
            )

        snapshot_hash = sha256(
            f"{title}\n{text}".encode("utf-8")
        ).hexdigest()

        return KnowledgeDocument(
            document_id=f"microsoft:page:{page_slug}",
            source_name="microsoft_learn",
            title=title,
            text=text,
            source_url=url,
            source_revision=f"sha256:{snapshot_hash}",
            retrieved_at=datetime.now(timezone.utc),
        )
