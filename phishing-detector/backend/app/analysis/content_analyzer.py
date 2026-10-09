import re
from typing import Iterable

from bs4 import BeautifulSoup

from app.analysis.brand_analyzer import BRAND_DOMAINS
from app.schemas.evidence import Evidence
from app.schemas.parsed_email import ParsedEmail

SOURCE = "content_analyzer"
CATEGORY = "CONTENT"

MAX_PHRASES = 3
MAX_PHRASE_LENGTH = 80

# ---------------------------------------------------------------------------
# Rule definitions. Patterns are matched case-insensitively against whitespace-normalized text.
# Request-style rules require an action verb in front of the sensitive item, so purely
# informational sentences ("The password policy was updated.") do not match.
# ---------------------------------------------------------------------------

_FILLER = r"(?:(?:your|the|this|that|our|all|any|a|an|us|me|valid|current|new|full|correct|following)\s+)"


def _compile(patterns: Iterable[str]) -> list[re.Pattern[str]]:
    return [re.compile(pattern, re.IGNORECASE) for pattern in patterns]


# Urgency: any "strong" match is enough; otherwise at least two distinct weak indicators.
_URGENCY_STRONG = _compile(
    [
        r"\baccount\b[^.!?]{0,40}?\bwill be\s+(?:\w+\s+){0,2}?(?:suspended|closed|locked|terminated|deactivated|disabled|limited|deleted|restricted|blocked)\b",
        r"\baccount\b[^.!?]{0,30}?\bhas been\s+(?:suspended|locked|limited|restricted|compromised|blocked|disabled)\b",
        r"\bfinal\s+(?:warning|notice|reminder)\b",
        r"\blast\s+chance\b",
        r"\bexpires?\s+(?:today|tonight|in\s+\d+\s*(?:hours?|hrs?|minutes?))\b",
        r"\bfailure\s+to\s+(?:comply|respond|verify|act|confirm|update)\b",
        r"\b(?:verify|confirm|update|respond|reply|act|click|log\s?in|sign\s?in|pay|reset|provide|submit)\b[^.!?]{0,40}?\b(?:immediately|right\s+away|asap)\b",
    ]
)
_URGENCY_WEAK = _compile(
    [
        r"\burgent(?:ly)?\b",
        r"\bimmediate(?:ly)?\b",
        r"\bact\s+now\b",
        r"\baction\s+(?:is\s+)?required\b",
        r"\bwithin\s+(?:the\s+next\s+)?\d+\s*(?:hours?|hrs?|minutes?|days?)\b",
        r"\bright\s+away\b|\basap\b",
        r"\btime[- ]sensitive\b",
        r"\bexpires?\s+soon\b",
    ]
)

_CREDENTIAL_VERBS = (
    r"(?:enter|provide|confirm|verify|submit|send|share|re-?enter|type|supply|give|input|disclose|reply\s+with)"
)
_CREDENTIAL_FILLER = (
    r"(?:(?:your|the|all|valid|current|new|full|correct|account|login|log-in|email|online|banking|"
    r"and|or|username|user\s+name|id)\s+){0,5}"
)
_CREDENTIALS = _compile(
    [
        rf"\b{_CREDENTIAL_VERBS}\s+{_CREDENTIAL_FILLER}"
        r"(?:passwords?|username|user\s+name|login\s+credentials?|login\s+details|login\s+information|credentials|passcode|pin(?:\s+code)?)\b",
        r"\b(?:sign|log)[- ]?in\s+(?:\w+\s+){0,2}?to\s+(?:verify|confirm|validate|restore|unlock|reactivate|secure)\b",
        r"\b(?:confirm|verify|validate)\s+your\s+(?:login|log-in|sign-in|signin)\b",
    ]
)

_OTP_NOUNS = (
    r"(?:otp|one[- ]time\s+(?:password|passcode|code|pin)|"
    r"(?:verification|security|authentication|auth|confirmation|sign-?in|login|mfa|2fa|two-factor|multi-factor)\s+code|"
    r"passcode)"
)
_OTP = _compile(
    [
        r"\b(?:reply\s+with|enter|provide|share|send|give|read\s+out|tell|forward|submit|type|input|confirm|disclose|verify)\s+"
        r"(?:(?:your|the|this|that|us|me|a|an|new|current|latest|received|sms|text|email|6-digit|six-digit)\s+){0,4}"
        rf"{_OTP_NOUNS}\b"
    ]
)

_VERIFICATION = _compile(
    [
        r"\b(?:verify|confirm|validate|re-?verify)\s+(?:your\s+|the\s+)?(?:account|identity)\b",
        r"\baccount\s+verification\b",
        r"\baccount\s+(?:requires|needs)\s+(?:to\s+be\s+)?verif\w*",
        r"\b(?:security|identity)\s+verification\b",
    ]
)

_PAYMENT_ITEMS = (
    r"(?:bank\s+(?:account\s+)?(?:details|information|number)|"
    r"(?:credit|debit)?\s*card\s+(?:details|number|information)|"
    r"billing\s+(?:information|details)|payment\s+(?:information|details)|"
    r"account\s+number|routing\s+number|iban|cvv|wallet\s+address|seed\s+phrase|recovery\s+phrase)"
)
_PAYMENT_NOUNS = r"(?:money|funds|payment|gift\s+cards?|bitcoin|btc|ethereum|usdt|crypto(?:currency)?)"
_PAYMENT = _compile(
    [
        rf"\b(?:provide|send|submit|enter|confirm|update|share|verify|give)\s+{_FILLER}{{0,3}}{_PAYMENT_ITEMS}\b",
        r"\bpay\s+(?:immediately|now|today|right\s+away)\b",
        r"\b(?:pay|settle|remit)\s+(?:(?:the|this|your|our|an|outstanding|overdue|unpaid|attached|full|remaining)\s+){0,4}"
        r"(?:invoice|bill|balance|fees?|amount|fine|penalty|charges?)\b",
        r"\b(?:make|initiate|complete|arrange|process)\s+(?:an?|the|this|your)\s+(?:urgent\s+)?(?:wire\s+transfer|bank\s+transfer|payment|transfer)\b",
        r"\b(?:transfer|wire|send|remit|deposit)\s+(?:(?:us|me|the|a|an|your|this|that|all|remaining|outstanding|full|\$?[\d,]+(?:\.\d+)?|usd|eur|gbp)\s+){0,4}"
        rf"{_PAYMENT_NOUNS}\b(?!\s+(?:confirmation|receipt|reminder|notice|policy|terms|history))",
        r"\b(?:pay|payment)\b[^.!?]{0,30}?\b(?:in|with|via|using)\s+(?:bitcoin|btc|ethereum|usdt|crypto(?:currency)?)\b",
    ]
)

# A strong CTA is suspicious by itself; a weak CTA only when another suspicious signal exists.
_CTA_STRONG = _compile(
    [
        r"\bverify\s+now\b",
        r"\blog\s?in\s+now\b",
        r"\bsign\s?in\s+now\b",
        r"\bconfirm\s+now\b",
        r"\bupdate\s+your\s+account\b",
        r"\bcomplete\s+(?:the\s+|your\s+)?(?:account\s+)?verification\b",
        r"\bsecure\s+your\s+account\b",
    ]
)
_CTA_WEAK = _compile([r"\bclick\s+(?:here|(?:on\s+)?the\s+link|below|(?:on\s+)?the\s+button)\b"])

_BRAND_ROLES = (
    r"(?:security|support|account(?:s)?(?:\s+team)?|team|customer\s+(?:service|support|care)|service|billing|"
    r"help\s?desk|notifications?|alerts?|fraud(?:\s+department)?)"
)

_GREETING = re.compile(
    r"\bdear\s+(?:valued\s+|esteemed\s+)?(?:customer|user|member|client|account\s*holder|email\s+user|sir\s*(?:/|or)\s*madam)\b",
    re.IGNORECASE,
)

# Words (up to a few) before a match that turn a request into a warning ("never share your OTP").
_NEGATION = re.compile(r"(?:\bnever|\bnot|n't|\bwithout|\bavoid)(?:\W+\w+){0,4}\W*$", re.IGNORECASE)


def _evidence(severity: float, reason: str, phrases: list[str]) -> Evidence:
    return Evidence(
        category=CATEGORY,
        severity=severity,
        reason=reason,
        observed_value="; ".join(phrases) if phrases else None,
        source=SOURCE,
    )


def _shorten(phrase: str) -> str:
    return phrase if len(phrase) <= MAX_PHRASE_LENGTH else phrase[: MAX_PHRASE_LENGTH - 3] + "..."


def _is_negated(text: str, start: int) -> bool:
    return bool(_NEGATION.search(text[max(0, start - 40) : start]))


def _find_phrases(
    patterns: Iterable[re.Pattern[str]], text: str, check_negation: bool = True
) -> list[str]:
    """Distinct (case-insensitive) matched phrases, in order of appearance."""
    found: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            if check_negation and _is_negated(text, match.start()):
                continue
            phrase = match.group(0)
            key = phrase.lower()
            if key not in seen:
                seen.add(key)
                found.append(_shorten(phrase))
    return found


def _html_to_text(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "head", "title"]):
            tag.decompose()
        return soup.get_text(" ")
    except Exception:
        return ""


def _normalize(text: str) -> str:
    text = text.replace("\u2019", "'").replace("\u2018", "'")
    return " ".join(text.split())


def _build_text(parsed_email: ParsedEmail) -> str:
    body = (parsed_email.plain_text_body or "").strip()
    if not body and parsed_email.html_body:
        body = _html_to_text(parsed_email.html_body)
    subject = (parsed_email.subject or "").strip()
    return _normalize(f"{subject}. {body}" if subject and body else subject or body)


def _check_urgency(text: str) -> list[str]:
    strong = _find_phrases(_URGENCY_STRONG, text)
    if strong:
        return strong
    weak_hits = [_find_phrases([pattern], text) for pattern in _URGENCY_WEAK]
    weak_hits = [hits for hits in weak_hits if hits]
    if len(weak_hits) >= 2:
        return [hits[0] for hits in weak_hits]
    return []


def _check_impersonation(text: str, signal_count: int) -> list[str]:
    if signal_count == 0:
        return []
    phrases: list[str] = []
    for brand in BRAND_DOMAINS:
        role = re.search(rf"\b{re.escape(brand)}\s+{_BRAND_ROLES}\b", text, re.IGNORECASE)
        mentioned = re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", text, re.IGNORECASE)
        if role:
            phrases.append(_shorten(role.group(0)))
        elif mentioned and signal_count >= 2:
            phrases.append(_shorten(mentioned.group(0)))
    return list(dict.fromkeys(phrases))


def analyze_content(parsed_email: ParsedEmail) -> list[Evidence]:
    """Rule-based social-engineering analysis of subject + body. Returns evidence only."""
    text = _build_text(parsed_email)
    if not text:
        return []

    urgency = _check_urgency(text)
    credentials = _find_phrases(_CREDENTIALS, text)
    otp = _find_phrases(_OTP, text)
    verification = _find_phrases(_VERIFICATION, text)
    payment = _find_phrases(_PAYMENT, text)

    suspicious_signals = [urgency, credentials, otp, verification, payment]
    signal_count = sum(1 for signal in suspicious_signals if signal)

    cta = _find_phrases(_CTA_STRONG, text, check_negation=False)
    if not cta and signal_count:
        cta = _find_phrases(_CTA_WEAK, text, check_negation=False)

    impersonation = _check_impersonation(text, signal_count + (1 if cta else 0))
    greeting = _GREETING.search(text)

    evidence: list[Evidence] = []
    rules = (
        (0.5, "Email uses strong urgency or threat language", urgency),
        (0.8, "Email requests sensitive account credentials", credentials),
        (0.8, "Email requests a security or verification code", otp),
        (0.5, "Email requests account or identity verification", verification),
        (0.7, "Email requests payment or sensitive financial information", payment),
        (0.35, "Email contains a suspicious call to action", cta),
        (0.4, "Email uses language associated with a known brand or service", impersonation),
    )
    for severity, reason, phrases in rules:
        if phrases:
            evidence.append(_evidence(severity, reason, phrases[:MAX_PHRASES]))
    if greeting:
        evidence.append(
            _evidence(0.15, "Email uses a generic recipient greeting", [greeting.group(0)])
        )
    return evidence
