from urllib.parse import urlsplit

import requests


MAX_DOWNLOAD_BYTES = 4 * 1024 * 1024


def download_microsoft_html(
    session: requests.Session,
    url: str,
) -> bytes:
    parsed = urlsplit(url)

    if (
        parsed.scheme != "https"
        or parsed.netloc != "learn.microsoft.com"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Expected an approved Microsoft Learn HTTPS URL.")

    with session.get(
        url,
        headers={
            "User-Agent": "CyberTriage/0.1",
            "Accept": "text/html",
        },
        timeout=(10, 30),
        stream=True,
        allow_redirects=False,
    ) as response:
        response.raise_for_status()

        if response.status_code != 200:
            raise RuntimeError(
                f"Unexpected Microsoft response: {response.status_code}"
            )

        content_type = response.headers.get("Content-Type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()

        if media_type != "text/html":
            raise ValueError("Expected a Microsoft HTML document.")

        content = bytearray()

        for block in response.iter_content(chunk_size=64 * 1024):
            if len(content) + len(block) > MAX_DOWNLOAD_BYTES:
                raise ValueError("Microsoft document exceeds download limit.")

            content.extend(block)

    return bytes(content)