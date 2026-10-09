import ipaddress
import re
from email.utils import parseaddr
from typing import Mapping, Optional

from app.schemas.evidence import Evidence
from app.schemas.parsed_email import ParsedEmail

SOURCE = "header_analyzer"
HEADER = "HEADER"
AUTHENTICATION = "AUTHENTICATION"

# Brand keyword -> registered domains that legitimately send mail for that brand.
# This is a small header-level heuristic list, not a lookalike-domain detector.
DEFAULT_BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "microsoft": frozenset(
        {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"}
    ),
    "google": frozenset({"google.com", "gmail.com", "googlemail.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "amazon": frozenset(
        {
            "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it",
            "amazon.es", "amazon.ca", "amazon.in", "amazon.co.jp", "amazon.com.au",
        }
    ),
    "netflix": frozenset({"netflix.com"}),
    "meta": frozenset({"meta.com", "facebook.com", "facebookmail.com", "fb.com"}),
    "facebook": frozenset({"facebook.com", "facebookmail.com", "fb.com"}),
    "instagram": frozenset({"instagram.com", "mail.instagram.com"}),
}

# Second-level labels commonly used under country-code TLDs (e.g. example.co.uk).
_COMMON_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}

_DOMAIN_LITERAL_PATTERN = re.compile(r"([^\s<>@]+@\[[0-9A-Fa-f:.]+\])")
_DOMAIN_PATTERN = re.compile(r"^[a-z0-9._-]+$")


def _extract_domain(address: str) -> Optional[str]:
    """Return the lowercase domain of an email address, or None if it is not valid."""
    if address.count("@") != 1:
        return None
    local, domain = address.split("@")
    domain = domain.strip().strip("[]").rstrip(".").lower()
    if not local or not domain:
        return None
    if _is_ip(domain):
        return domain
    if not _DOMAIN_PATTERN.match(domain) or "." not in domain:
        return None
    return domain


def _parse_sender(header_value: Optional[str]) -> tuple[str, Optional[str], Optional[str]]:
    """Return (display_name, address, domain) for an address header."""
    if not header_value:
        return "", None, None
    name, address = parseaddr(header_value)
    if not address:
        # parseaddr rejects domain literals such as user@[203.0.113.9].
        literal = _DOMAIN_LITERAL_PATTERN.search(header_value)
        if literal:
            address = literal.group(1)
            name = header_value[: literal.start()].replace("<", "").strip().strip('"').strip()
    address = address.strip()
    return name.strip(), (address or None), (_extract_domain(address) if address else None)


def _parse_message_id_domain(message_id: Optional[str]) -> Optional[str]:
    if not message_id:
        return None
    value = message_id.strip().strip("<>").strip()
    if "@" not in value:
        return None
    return _extract_domain("x@" + value.rpartition("@")[2])


def _is_ip(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain.strip("[]"))
        return True
    except ValueError:
        return False


def _registered_domain(domain: str) -> str:
    """Approximate the registrable domain without a public-suffix list."""
    if _is_ip(domain):
        return domain
    labels = domain.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _COMMON_SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _domains_differ(first: str, second: str) -> bool:
    return _registered_domain(first) != _registered_domain(second)


def _check_reply_to(
    parsed_email: ParsedEmail, sender_address: Optional[str], sender_domain: Optional[str]
) -> Optional[Evidence]:
    _, reply_address, reply_domain = _parse_sender(parsed_email.reply_to)
    if not (sender_address and sender_domain and reply_address and reply_domain):
        return None
    if not _domains_differ(sender_domain, reply_domain):
        return None
    return Evidence(
        category=HEADER,
        severity=0.8,
        reason="Reply-To domain differs from sender domain",
        observed_value=f"{sender_address} -> {reply_address}",
        source=SOURCE,
    )


def _check_return_path(
    parsed_email: ParsedEmail, sender_address: Optional[str], sender_domain: Optional[str]
) -> Optional[Evidence]:
    _, return_address, return_domain = _parse_sender(parsed_email.return_path)
    if not (sender_address and sender_domain and return_address and return_domain):
        return None
    if not _domains_differ(sender_domain, return_domain):
        return None
    return Evidence(
        category=HEADER,
        severity=0.7,
        reason="Return-Path domain differs from sender domain",
        observed_value=f"{sender_address} -> {return_address}",
        source=SOURCE,
    )


def _check_authentication(parsed_email: ParsedEmail) -> list[Evidence]:
    checks = (
        ("SPF", parsed_email.spf, 0.9),
        ("DKIM", parsed_email.dkim, 0.8),
        ("DMARC", parsed_email.dmarc, 0.95),
    )
    return [
        Evidence(
            category=AUTHENTICATION,
            severity=severity,
            reason=f"{label} authentication failed",
            observed_value=f"{label.lower()}=fail",
            source=SOURCE,
        )
        for label, result, severity in checks
        if (result or "").lower() == "fail"
    ]


def _check_display_name_brand(
    display_name: str,
    sender_domain: Optional[str],
    brand_domains: Mapping[str, frozenset[str]],
) -> Optional[Evidence]:
    if not display_name or not sender_domain:
        return None
    registered = _registered_domain(sender_domain)
    for brand, legitimate_domains in brand_domains.items():
        if not re.search(rf"\b{re.escape(brand)}\b", display_name, re.IGNORECASE):
            continue
        if registered in legitimate_domains:
            continue
        return Evidence(
            category=HEADER,
            severity=0.75,
            reason="Display name may impersonate a known brand",
            observed_value=f'"{display_name}" sent from {sender_domain}',
            source=SOURCE,
        )
    return None


def _check_message_id(
    parsed_email: ParsedEmail, sender_domain: Optional[str]
) -> Optional[Evidence]:
    message_id_domain = _parse_message_id_domain(parsed_email.message_id)
    if not sender_domain or not message_id_domain:
        return None
    if not _domains_differ(sender_domain, message_id_domain):
        return None
    return Evidence(
        category=HEADER,
        severity=0.4,
        reason="Message-ID domain differs from sender domain",
        observed_value=f"{sender_domain} -> {message_id_domain}",
        source=SOURCE,
    )


def _check_sender_domain(from_header: Optional[str], sender_domain: Optional[str]) -> list[Evidence]:
    # A completely absent From header is missing information, not evidence.
    if not from_header or not from_header.strip():
        return []

    if sender_domain is None:
        return [
            Evidence(
                category=HEADER,
                severity=0.5,
                reason="Sender domain is missing or invalid",
                observed_value=from_header,
                source=SOURCE,
            )
        ]

    evidence: list[Evidence] = []
    if _is_ip(sender_domain):
        evidence.append(
            Evidence(
                category=HEADER,
                severity=0.7,
                reason="Sender domain is an IP address",
                observed_value=sender_domain,
                source=SOURCE,
            )
        )
    if any(label.startswith("xn--") for label in sender_domain.split(".")):
        evidence.append(
            Evidence(
                category=HEADER,
                severity=0.6,
                reason="Sender domain uses punycode (xn--)",
                observed_value=sender_domain,
                source=SOURCE,
            )
        )
    return evidence


def analyze_headers(
    parsed_email: ParsedEmail,
    brand_domains: Optional[Mapping[str, frozenset[str]]] = None,
) -> list[Evidence]:
    """Analyze parsed email headers and return evidence. Missing data is never evidence."""
    brands = DEFAULT_BRAND_DOMAINS if brand_domains is None else brand_domains
    display_name, sender_address, sender_domain = _parse_sender(parsed_email.from_)

    evidence: list[Evidence] = []
    evidence.extend(_check_sender_domain(parsed_email.from_, sender_domain))

    for item in (
        _check_reply_to(parsed_email, sender_address, sender_domain),
        _check_return_path(parsed_email, sender_address, sender_domain),
    ):
        if item:
            evidence.append(item)

    evidence.extend(_check_authentication(parsed_email))

    for item in (
        _check_display_name_brand(display_name, sender_domain, brands),
        _check_message_id(parsed_email, sender_domain),
    ):
        if item:
            evidence.append(item)

    return evidence
