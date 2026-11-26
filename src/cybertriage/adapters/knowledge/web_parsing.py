"""Extract official documentation articles, not navigation, scripts or page actions."""

import re
from datetime import datetime
from hashlib import sha256

from bs4 import BeautifulSoup

from cybertriage.application.policies.live_web import validate_target_url
from cybertriage.domain.knowledge import KnowledgeDocument
from cybertriage.domain.live_web import WEB_DOCUMENT_POLICY, WebFetchError, WebResponse, WebTarget


class OfficialDocumentationParser:
    def parse(self, target: WebTarget, response: WebResponse, fetched_at: datetime) -> KnowledgeDocument:
        try:
            return self._parse(target, response, fetched_at)
        except (ValueError, TypeError, RecursionError) as error:
            raise WebFetchError("Public documentation could not be parsed safely.") from error

    def _parse(self, target: WebTarget, response: WebResponse, fetched_at: datetime) -> KnowledgeDocument:
        url = validate_target_url(target, response.url)
        if response.status != 200 or not response.body or len(response.body) > 2 * 1024 * 1024:
            raise WebFetchError("Invalid documentation input.")
        soup = BeautifulSoup(response.body, "html.parser")
        for element in soup.select("script,style,nav,form,button,iframe,footer,.metadata"):
            element.decompose()
        platforms = ()
        if target.source == "microsoft":
            heading = soup.select_one("main h1")
            articles = [element for element in soup.select("main .content") if element.find(["p", "table", "ul", "ol", "pre"]) is not None]
            if len(articles) != 1:
                semantic = soup.select("main article")
                articles = semantic if len(semantic) == 1 else [element for element in soup.select("main") if element.find(["p", "table"]) is not None]
            if heading is None or len(articles) != 1:
                raise WebFetchError("Microsoft article structure was not recognized.")
            title = heading.get_text(" ", strip=True)
            text = articles[0].get_text("\n", strip=True)
            identity = re.match(rf"^{re.escape(target.identifier)}(?:\D|$)", title)
            explicit = re.search(rf"\b{re.escape(target.identifier)}\s*\([SF](?:\s*,\s*[SF])*\)", text)
            row = any(re.fullmatch(rf"{re.escape(target.identifier)}(?:\s*\([SF](?:\s*,\s*[SF])*\))?", cells[0].get_text(" ", strip=True))
                      for table_row in articles[0].select("tr") if (cells := table_row.find_all(["td", "th"], recursive=False)))
            if not identity and not explicit and not row:
                raise WebFetchError("Microsoft article does not include the requested event ID.")
            if not row and not any(marker in text for marker in ("Event Description", "Event description", "<EventID>", "Subcategory:")):
                raise WebFetchError("Microsoft response lacks event documentation content.")
            platforms = ("Windows",)
        elif target.source == "mitre":
            scope = soup.select_one("main article") or soup.select_one("main") or soup.select_one("article") or soup.select_one("body") or soup
            heading = scope.select_one("h1")
            descriptions = soup.select(".description-body")
            if heading is None:
                raise WebFetchError("ATT&CK article structure was not recognized.")
            identity = next((item for item in soup.select(".card-data")
                             if re.match(rf"ID:\s*{re.escape(target.identifier)}(?:\s|$)", item.get_text(" ", strip=True))), None)
            labelled_identity = re.search(rf"(?:^|\n)ID:\s*{re.escape(target.identifier)}(?:\s|$)", scope.get_text("\n", strip=True))
            if identity is None and labelled_identity is None:
                raise WebFetchError("ATT&CK article identity was not confirmed.")
            title = f"{target.identifier}: {heading.get_text(' ', strip=True)}"
            if descriptions:
                text = "\n\n".join(element.get_text("\n", strip=True) for element in descriptions)
            else:
                paragraphs = []
                for element in heading.find_all_next(["p", "h2"]):
                    if element.name == "h2":
                        break
                    paragraphs.append(element.get_text("\n", strip=True))
                text = "\n\n".join(paragraphs)
            for item in soup.select(".card-data"):
                label = item.get_text(" ", strip=True)
                if re.match(r"Platforms?:", label):
                    values = [value.strip() for value in label.split(":", 1)[1].split(",")]
                    if not all(values) or len(values) > 32 or any(len(value) > 64 for value in values):
                        raise WebFetchError("Invalid ATT&CK platform metadata.")
                    platforms = tuple(values)
                    break
            if not platforms:
                for row in heading.find_all_next(["tr", "h2"]):
                    if row.name == "h2":
                        break
                    cells = row.find_all(["td", "th"], recursive=False)
                    if len(cells) == 2 and re.fullmatch(r"Platforms?:?", cells[0].get_text(" ", strip=True)):
                        values = [value.strip() for value in cells[1].get_text(" ", strip=True).split(",")]
                        if all(values) and len(values) <= 32 and all(len(value) <= 64 for value in values):
                            platforms = tuple(values)
                        break
        else:
            raise WebFetchError("Unsupported public documentation source.")
        if len(title) > 512 or not title.strip() or not 100 <= len(text) <= 150000:
            raise WebFetchError("Documentation article is empty, insufficient or oversized.")
        digest = sha256(f"{title}\n{text}".encode("utf-8")).hexdigest()
        return KnowledgeDocument(f"live:{target.source}:{target.identifier}", f"live_{target.source}", title, text,
                                  url, f"{WEB_DOCUMENT_POLICY}:sha256:{digest}", fetched_at, platforms)
