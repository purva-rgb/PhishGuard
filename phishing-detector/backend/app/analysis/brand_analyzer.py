import re
from typing import Mapping, Optional

from rapidfuzz.distance import Levenshtein

from app.preprocessing.url_utils import URLParts, parse_url
from app.schemas.evidence import Evidence
from app.schemas.url import ExtractedURL

SOURCE = "brand_analyzer"
CATEGORY = "BRAND"

# Brand keyword -> registrable domains that legitimately belong to the brand.
BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "microsoft": frozenset(
        {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"}
    ),
    "google": frozenset(
        {
            "google.com", "gmail.com", "googlemail.com", "googleusercontent.com",
            "googleapis.com", "google.co.uk", "google.co.in", "google.de", "google.ca",
        }
    ),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "amazon": frozenset(
        {
            "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it",
            "amazon.es", "amazon.ca", "amazon.in", "amazon.co.jp", "amazon.com.au",
            "amazonaws.com",
        }
    ),
    "netflix": frozenset({"netflix.com"}),
    "meta": frozenset({"meta.com", "facebook.com", "facebookmail.com", "fb.com"}),
    "facebook": frozenset({"facebook.com", "facebookmail.com", "fb.com"}),
    "instagram": frozenset({"instagram.com"}),
}

# Brands at least this long may match as a substring of a hostname label (e.g. "paypalsecure").
# Shorter brands (apple, meta) must match a whole label token to avoid false positives.
_SUBSTRING_MIN_LENGTH = 6
# Typo-style lookalikes (edit distance 1) are only checked for brands at least this long.
_TYPO_MIN_LENGTH = 6

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"})


def find_brands_in_text(text: str, brands: Optional[Mapping[str, frozenset[str]]] = None) -> list[str]:
    """Return brand keywords that appear as whole words in free text (e.g. link text)."""
    brands = BRAND_DOMAINS if brands is None else brands
    return [
        brand
        for brand in brands
        if re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", text, re.IGNORECASE)
    ]


def is_legitimate_domain_for_brand(
    registrable_domain: Optional[str],
    brand: str,
    brands: Optional[Mapping[str, frozenset[str]]] = None,
) -> bool:
    brands = BRAND_DOMAINS if brands is None else brands
    return registrable_domain is not None and registrable_domain in brands.get(brand, frozenset())


def _hostname_tokens(parts: URLParts) -> list[str]:
    """Tokens from subdomains and the registrable domain name (excluding the public suffix)."""
    labels = list(parts.subdomain_labels)
    if parts.registrable_domain:
        labels.append(parts.registrable_domain.split(".")[0])
    tokens: list[str] = []
    for label in labels:
        tokens.extend(token for token in re.split(r"[-_.]", label) if token)
    return tokens


def _path_tokens(parts: URLParts) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9]+", f"{parts.path} {parts.query}".lower()) if token]


def _mentions_brand(brand: str, tokens: list[str]) -> bool:
    for token in tokens:
        if token == brand:
            return True
        if len(brand) >= _SUBSTRING_MIN_LENGTH and brand in token:
            return True
    return False


def _lookalike_of(token: str, brand: str) -> bool:
    if token == brand or len(token) < 4:
        return False
    if token.replace("rn", "m").translate(_HOMOGLYPHS) == brand:
        return True
    return len(brand) >= _TYPO_MIN_LENGTH and Levenshtein.distance(token, brand) == 1


def analyze_url_brand(
    extracted_url: ExtractedURL,
    brands: Optional[Mapping[str, frozenset[str]]] = None,
) -> list[Evidence]:
    """Detect brand names and obvious lookalikes in a URL whose domain is not the brand's."""
    brands = BRAND_DOMAINS if brands is None else brands
    parts = parse_url(extracted_url.url)
    if not parts.hostname:
        return []

    # A URL on any known brand's own domain is not impersonation.
    if parts.registrable_domain and any(
        parts.registrable_domain in domains for domains in brands.values()
    ):
        return []

    actual = parts.registrable_domain or parts.hostname
    host_tokens = [] if parts.is_ip else _hostname_tokens(parts)
    path_tokens = _path_tokens(parts)

    evidence: list[Evidence] = []
    for brand in brands:
        if _mentions_brand(brand, host_tokens):
            evidence.append(
                Evidence(
                    category=CATEGORY,
                    severity=0.85,
                    reason="Possible brand impersonation in URL",
                    observed_value=f"{brand} -> {actual}",
                    source=SOURCE,
                )
            )
            continue

        lookalike = next((token for token in host_tokens if _lookalike_of(token, brand)), None)
        if lookalike:
            evidence.append(
                Evidence(
                    category=CATEGORY,
                    severity=0.9,
                    reason="Possible brand lookalike domain in URL",
                    observed_value=f"{lookalike} resembles {brand} -> {actual}",
                    source=SOURCE,
                )
            )
            continue

        if _mentions_brand(brand, path_tokens):
            evidence.append(
                Evidence(
                    category=CATEGORY,
                    severity=0.5,
                    reason="Possible brand impersonation in URL",
                    observed_value=f"{brand} (in URL path) -> {actual}",
                    source=SOURCE,
                )
            )
    return evidence
