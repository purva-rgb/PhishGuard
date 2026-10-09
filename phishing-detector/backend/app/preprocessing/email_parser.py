import re
from email import message_from_string, policy
from email.message import Message
from email.utils import formataddr, getaddresses
from typing import Optional

from app.schemas.parsed_email import ParsedEmail

UNKNOWN = "unknown"

_ALLOWED_RESULTS = {
    "spf": {"pass", "fail", "softfail", "neutral", "none"},
    "dkim": {"pass", "fail", "neutral", "none"},
    "dmarc": {"pass", "fail", "none"},
}

_AUTH_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)", re.IGNORECASE)


def _clean(value: object) -> Optional[str]:
    """Convert a header value to a single-line string, or None if empty."""
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text or None


def _get_header(msg: Message, name: str) -> Optional[str]:
    try:
        return _clean(msg.get(name))
    except Exception:
        return None


def _get_all_headers(msg: Message, name: str) -> list[str]:
    try:
        values = msg.get_all(name) or []
    except Exception:
        return []
    cleaned = (_clean(value) for value in values)
    return [value for value in cleaned if value]


def _get_address_list(msg: Message, name: str) -> list[str]:
    addresses: list[str] = []
    for header_value in _get_all_headers(msg, name):
        for display_name, address in getaddresses([header_value]):
            if address:
                addresses.append(formataddr((display_name, address)))
            elif display_name:
                addresses.append(display_name)
    return addresses


def _parse_authentication_results(header_values: list[str]) -> dict[str, str]:
    """Read SPF/DKIM/DMARC results already present in Authentication-Results.

    No verification is performed. The first result found for each mechanism is used.
    """
    results = {"spf": UNKNOWN, "dkim": UNKNOWN, "dmarc": UNKNOWN}
    seen: set[str] = set()
    for header_value in header_values:
        for mechanism, result in _AUTH_RESULT_PATTERN.findall(header_value):
            mechanism = mechanism.lower()
            if mechanism in seen:
                continue
            seen.add(mechanism)
            result = result.lower()
            if result in _ALLOWED_RESULTS[mechanism]:
                results[mechanism] = result
    return results


def _decode_part(part: Message) -> Optional[str]:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None

    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else None

    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeError):
        return payload.decode("utf-8", errors="replace")


def _extract_bodies(msg: Message) -> tuple[Optional[str], Optional[str]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment":
            continue

        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue

        text = _decode_part(part)
        if text is None:
            continue
        (plain_parts if content_type == "text/plain" else html_parts).append(text)

    plain = "\n".join(plain_parts) if plain_parts else None
    html = "\n".join(html_parts) if html_parts else None
    return plain, html


def parse_email(email_text: str) -> ParsedEmail:
    """Parse raw email text into a ParsedEmail. Never raises on malformed input."""
    try:
        msg = message_from_string(email_text, policy=policy.default)
    except Exception:
        return ParsedEmail()

    auth_headers = _get_all_headers(msg, "Authentication-Results")
    auth = _parse_authentication_results(auth_headers)

    try:
        plain_body, html_body = _extract_bodies(msg)
    except Exception:
        plain_body, html_body = None, None

    return ParsedEmail(
        from_=_get_header(msg, "From"),
        to=_get_address_list(msg, "To"),
        cc=_get_address_list(msg, "Cc"),
        reply_to=_get_header(msg, "Reply-To"),
        return_path=_get_header(msg, "Return-Path"),
        subject=_get_header(msg, "Subject"),
        date=_get_header(msg, "Date"),
        message_id=_get_header(msg, "Message-ID"),
        received=_get_all_headers(msg, "Received"),
        authentication_results="; ".join(auth_headers) if auth_headers else None,
        spf=auth["spf"],
        dkim=auth["dkim"],
        dmarc=auth["dmarc"],
        plain_text_body=plain_body,
        html_body=html_body,
    )
