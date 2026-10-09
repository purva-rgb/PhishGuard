import ipaddress
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

import tldextract

# Offline extractor: uses the public-suffix snapshot bundled with tldextract (no network access).
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


@dataclass(frozen=True)
class URLParts:
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    registrable_domain: Optional[str] = None
    subdomain_labels: list[str] = field(default_factory=list)
    path: str = ""
    query: str = ""
    has_userinfo: bool = False
    is_ip: bool = False


def clean_url(url: str) -> str:
    """Trim whitespace and stray line breaks without otherwise modifying the URL."""
    return url.strip().replace("\r", "").replace("\n", "").replace("\t", "")


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def parse_url(url: str) -> URLParts:
    """Split a URL into the parts used by the analyzers. Never raises."""
    try:
        split = urlsplit(clean_url(url))
        hostname = split.hostname
    except ValueError:
        return URLParts()

    scheme = split.scheme.lower() or None
    if not hostname:
        return URLParts(scheme=scheme, path=split.path, query=split.query)

    hostname = hostname.rstrip(".").lower()
    has_userinfo = "@" in split.netloc

    if is_ip_address(hostname):
        return URLParts(
            scheme=scheme,
            hostname=hostname,
            path=split.path,
            query=split.query,
            has_userinfo=has_userinfo,
            is_ip=True,
        )

    try:
        extracted = _EXTRACTOR(hostname)
        registrable = extracted.top_domain_under_public_suffix or None
        subdomains = [label for label in extracted.subdomain.split(".") if label]
    except Exception:
        registrable, subdomains = None, []

    return URLParts(
        scheme=scheme,
        hostname=hostname,
        registrable_domain=registrable,
        subdomain_labels=subdomains,
        path=split.path,
        query=split.query,
        has_userinfo=has_userinfo,
    )


def registrable_domain_of(host_or_domain: str) -> Optional[str]:
    """Registrable domain for a bare hostname (e.g. 'mail.example.co.uk' -> 'example.co.uk')."""
    try:
        return _EXTRACTOR(host_or_domain.lower()).top_domain_under_public_suffix or None
    except Exception:
        return None


def normalize_url(url: str) -> str:
    """Build a comparison key. The original URL is never replaced by this value."""
    cleaned = clean_url(url)
    try:
        split = urlsplit(cleaned)
        host = (split.hostname or "").lower()
        port = f":{split.port}" if split.port else ""
    except ValueError:
        return cleaned.lower()

    userinfo = split.netloc.rpartition("@")[0]
    authority = f"{userinfo}@{host}{port}" if userinfo else f"{host}{port}"
    path = split.path.rstrip("/")
    query = f"?{split.query}" if split.query else ""
    return f"{split.scheme.lower()}://{authority}{path}{query}"
