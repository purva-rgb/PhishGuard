import re
from html.parser import HTMLParser
from typing import Optional

from app.preprocessing.url_utils import clean_url, normalize_url
from app.schemas.parsed_email import ParsedEmail
from app.schemas.url import ExtractedURL

_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?"
_CLOSING_BRACKETS = {")": "(", "]": "[", "}": "{"}


class _LinkCollector(HTMLParser):
    """Collect <a href> links (with anchor text) and visible text outside of links."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, Optional[str]]] = []
        self.text_chunks: list[str] = []
        self._href: Optional[str] = None
        self._anchor_chunks: list[str] = []
        self._ignored_depth = 0

    def _finish_anchor(self) -> None:
        if self._href is not None:
            anchor = " ".join("".join(self._anchor_chunks).split()) or None
            self.links.append((self._href, anchor))
        self._href = None
        self._anchor_chunks = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag in ("script", "style"):
            self._ignored_depth += 1
        elif tag == "a":
            self._finish_anchor()
            href = dict(attrs).get("href")
            if href and href.strip():
                self._href = href

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._ignored_depth = max(0, self._ignored_depth - 1)
        elif tag == "a":
            self._finish_anchor()

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        if self._href is not None:
            self._anchor_chunks.append(data)
        else:
            self.text_chunks.append(data)

    def close(self) -> None:
        super().close()
        self._finish_anchor()


def _strip_trailing_junk(url: str) -> str:
    while url:
        last = url[-1]
        if last in _TRAILING_PUNCTUATION:
            url = url[:-1]
        elif last in _CLOSING_BRACKETS and url.count(last) > url.count(_CLOSING_BRACKETS[last]):
            url = url[:-1]
        else:
            break
    return url


def _find_urls_in_text(text: str) -> list[str]:
    urls = []
    for match in _URL_PATTERN.finditer(text):
        url = _strip_trailing_junk(match.group(0).replace("&amp;", "&"))
        if url:
            urls.append(url)
    return urls


def _is_http_url(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))


def extract_urls(parsed_email: ParsedEmail) -> list[ExtractedURL]:
    """Extract unique URLs (with anchor text for HTML links) from the email bodies."""
    candidates: list[tuple[str, Optional[str]]] = []

    if parsed_email.html_body:
        collector = _LinkCollector()
        try:
            collector.feed(parsed_email.html_body)
            collector.close()
        except Exception:
            pass
        for href, anchor in collector.links:
            href = clean_url(href)
            if _is_http_url(href):
                candidates.append((href, anchor))
        for chunk in collector.text_chunks:
            candidates.extend((url, None) for url in _find_urls_in_text(chunk))

    if parsed_email.plain_text_body:
        candidates.extend((url, None) for url in _find_urls_in_text(parsed_email.plain_text_body))

    results: list[ExtractedURL] = []
    index_by_key: dict[str, int] = {}
    for url, anchor in candidates:
        key = normalize_url(url)
        if key in index_by_key:
            existing = results[index_by_key[key]]
            if existing.anchor_text is None and anchor:
                existing.anchor_text = anchor
            continue
        index_by_key[key] = len(results)
        results.append(ExtractedURL(url=url, anchor_text=anchor))
    return results
