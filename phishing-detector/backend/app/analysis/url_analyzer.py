import re
from typing import Optional

from app.analysis.brand_analyzer import (
    analyze_url_brand,
    find_brands_in_text,
    is_legitimate_domain_for_brand,
)
from app.preprocessing.url_utils import URLParts, parse_url, registrable_domain_of
from app.schemas.evidence import Evidence
from app.schemas.url import ExtractedURL, URLAnalysis

SOURCE = "url_analyzer"

# Heuristic thresholds and lists (configurable).
LONG_URL_LENGTH = 150
MAX_SUBDOMAIN_LABELS = 3
MAX_PATH_DEPTH = 5
SUSPICIOUS_TLDS = frozenset({"xyz", "top", "click", "shop", "work", "zip", "tk", "ml", "ga", "cf"})
SUSPICIOUS_KEYWORDS = (
    "login", "verify", "verification", "secure", "account", "update", "password",
    "signin", "authenticate", "confirm", "billing", "payment", "wallet",
)
MIN_KEYWORDS_TO_FLAG = 2

# Structural thresholds: only clearly unusual values produce evidence.
MAX_HOST_DIGITS = 5
MAX_HOST_HYPHENS = 3
MAX_SPECIAL_CHARS = 10

_DOMAIN_IN_TEXT = re.compile(r"(?<![\w@.-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", re.IGNORECASE)
_SPECIAL_CHAR_EXCLUSIONS = set("-._~:/?#=&")


def _evidence(
    category: str, severity: float, reason: str, observed_value: Optional[str] = None
) -> Evidence:
    return Evidence(
        category=category,
        severity=severity,
        reason=reason,
        observed_value=observed_value,
        source=SOURCE,
    )


def _found_keywords(parts: URLParts) -> list[str]:
    text = f"{parts.hostname or ''} {parts.path} {parts.query}".lower()
    found: list[str] = []
    for token in re.split(r"[^a-z0-9]+", text):
        if token.endswith("s") and token[:-1] in SUSPICIOUS_KEYWORDS:
            token = token[:-1]
        if token in SUSPICIOUS_KEYWORDS and token not in found:
            found.append(token)
    return found


def _structural_issues(url: str, parts: URLParts) -> list[str]:
    issues: list[str] = []
    if parts.hostname and not parts.is_ip:
        digits = sum(char.isdigit() for char in parts.hostname)
        hyphens = parts.hostname.count("-")
        if digits > MAX_HOST_DIGITS:
            issues.append(f"{digits} digits in hostname")
        if hyphens > MAX_HOST_HYPHENS:
            issues.append(f"{hyphens} hyphens in hostname")
    special = sum(1 for char in url if not char.isalnum() and char not in _SPECIAL_CHAR_EXCLUSIONS)
    if special > MAX_SPECIAL_CHARS:
        issues.append(f"{special} special characters")
    return issues


def _anchor_mismatch(extracted_url: ExtractedURL, parts: URLParts) -> Optional[Evidence]:
    anchor = (extracted_url.anchor_text or "").strip()
    if not anchor or not parts.hostname:
        return None

    destination = parts.registrable_domain or parts.hostname
    mismatch = False

    # Link text that names a domain/URL different from the real destination.
    for candidate in _DOMAIN_IN_TEXT.findall(anchor):
        shown = registrable_domain_of(candidate)
        if shown and shown != parts.registrable_domain:
            mismatch = True
            break

    # Link text that names a known brand while the destination is not that brand's domain.
    if not mismatch:
        mismatch = any(
            not is_legitimate_domain_for_brand(parts.registrable_domain, brand)
            for brand in find_brands_in_text(anchor)
        )

    if not mismatch:
        return None
    shown_text = anchor if len(anchor) <= 80 else anchor[:77] + "..."
    return _evidence(
        "URL", 0.85, "Link text does not match the actual destination", f"{shown_text} -> {destination}"
    )


def analyze_url(extracted_url: ExtractedURL) -> list[Evidence]:
    """URL-structure analysis. Returns evidence only; brand checks live in brand_analyzer."""
    url = extracted_url.url.strip()
    parts = parse_url(url)
    evidence: list[Evidence] = []

    if len(url) > LONG_URL_LENGTH:
        evidence.append(_evidence("URL", 0.5, "URL is unusually long", f"{len(url)} characters"))

    if parts.is_ip:
        evidence.append(
            _evidence("URL", 0.8, "URL uses an IP address instead of a domain", parts.hostname)
        )

    if parts.has_userinfo:
        evidence.append(
            _evidence(
                "URL",
                0.9,
                "URL contains an @ symbol that may obscure the destination",
                f"actual host: {parts.hostname}" if parts.hostname else url,
            )
        )

    if parts.hostname and any(label.startswith("xn--") for label in parts.hostname.split(".")):
        evidence.append(_evidence("URL", 0.7, "URL uses a punycode domain", parts.hostname))

    if parts.scheme == "http":
        evidence.append(_evidence("URL", 0.3, "URL does not use HTTPS", url))

    if len(parts.subdomain_labels) > MAX_SUBDOMAIN_LABELS:
        evidence.append(
            _evidence(
                "DOMAIN",
                0.5,
                "URL contains an unusually deep subdomain structure",
                f"{parts.hostname} ({len(parts.subdomain_labels)} subdomain labels)",
            )
        )

    if parts.hostname and not parts.is_ip:
        tld = parts.hostname.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            evidence.append(
                _evidence(
                    "DOMAIN", 0.4, "URL uses a potentially suspicious top-level domain", f".{tld}"
                )
            )

    keywords = _found_keywords(parts)
    if len(keywords) >= MIN_KEYWORDS_TO_FLAG:
        evidence.append(
            _evidence("URL", 0.4, "URL contains security-sensitive keywords", ", ".join(keywords))
        )

    path_depth = len([segment for segment in parts.path.split("/") if segment])
    if path_depth > MAX_PATH_DEPTH:
        evidence.append(
            _evidence("URL", 0.3, "URL has an unusually deep path", f"{path_depth} path segments")
        )

    issues = _structural_issues(url, parts)
    if issues:
        evidence.append(_evidence("URL", 0.3, "URL has an unusual structure", "; ".join(issues)))

    mismatch = _anchor_mismatch(extracted_url, parts)
    if mismatch:
        evidence.append(mismatch)

    return evidence


def build_url_analysis(extracted_url: ExtractedURL) -> URLAnalysis:
    """Combine URL parts with URL-structure and brand evidence for one URL."""
    parts = parse_url(extracted_url.url)
    return URLAnalysis(
        url=extracted_url.url,
        hostname=parts.hostname,
        registrable_domain=parts.registrable_domain,
        scheme=parts.scheme,
        evidence=analyze_url(extracted_url) + analyze_url_brand(extracted_url),
    )
