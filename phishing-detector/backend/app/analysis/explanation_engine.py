"""Deterministic, evidence-based explanations for an already-calculated RiskResult.

This module never changes the score, verdict, confidence or evidence; it only describes them.
"""

from app.analysis.risk_engine import BRAND_IN_URL_REASON, BRAND_IN_URL_STRONG_MIN_SEVERITY
from app.schemas.evidence import Evidence
from app.schemas.explanation import ExplanationReason, ExplanationResult
from app.schemas.risk import RiskResult

MAX_REASONS = 5
MAX_OBSERVED_LENGTH = 120
GENERIC_FALLBACK = "Suspicious activity was detected in the email."

SUMMARIES = {
    "MALICIOUS": "Multiple strong phishing indicators were detected.",
    "SUSPICIOUS": "Some phishing indicators were detected, but the evidence is not conclusive.",
    "SAFE": "No major phishing indicators were detected. This does not guarantee the email is safe.",
}

RECOMMENDED_ACTIONS = {
    "MALICIOUS": (
        "Do not click links or provide credentials. Verify the sender through an independent "
        "trusted channel and report the email."
    ),
    "SUSPICIOUS": (
        "Do not click links or provide sensitive information until the sender and request are "
        "independently verified."
    ),
    "SAFE": (
        "No major phishing indicators were detected. Still verify unexpected requests before "
        "taking action."
    ),
}

# --- Ranking priorities (lower number = shown first) ---------------------------------------------

P_AUTHENTICATION = 1
P_BRAND = 2
P_URL_DESTINATION = 3
P_HEADER_MISMATCH = 4
P_CREDENTIAL_OTP = 5
P_PAYMENT = 6
P_VERIFICATION = 7
P_URGENCY = 8
P_MINOR = 9  # weak structural signals, CTA, content brand language, unknown reasons
P_GREETING = 10
DEFAULT_PRIORITY = P_MINOR

# Keys are the exact reason strings emitted by the Part 3-5 analyzers.
# Each value is (user-facing explanation, ranking priority).
REASON_EXPLANATIONS: dict[str, tuple[str, int]] = {
    # Header / authentication
    "DMARC authentication failed": ("The sender failed DMARC email authentication.", P_AUTHENTICATION),
    "SPF authentication failed": ("The sender failed SPF email authentication.", P_AUTHENTICATION),
    "DKIM authentication failed": ("The sender failed DKIM email authentication.", P_AUTHENTICATION),
    "Display name may impersonate a known brand": (
        "The sender's display name appears to impersonate a known brand.",
        P_BRAND,
    ),
    "Reply-To domain differs from sender domain": (
        "The Reply-To address uses a different domain from the sender.",
        P_HEADER_MISMATCH,
    ),
    "Return-Path domain differs from sender domain": (
        "The return address uses a different domain from the sender.",
        P_HEADER_MISMATCH,
    ),
    "Sender domain is an IP address": (
        "The sender uses an IP address instead of a normal domain.",
        P_HEADER_MISMATCH,
    ),
    "Sender domain uses punycode (xn--)": (
        "The sender domain uses punycode, which can be associated with lookalike domains.",
        P_HEADER_MISMATCH,
    ),
    "Sender domain is missing or invalid": (
        "The sender address does not contain a valid domain.",
        P_HEADER_MISMATCH,
    ),
    "Message-ID domain differs from sender domain": (
        "The message ID domain differs from the sender domain.",
        P_MINOR,
    ),
    # URL / domain / brand
    "Possible brand lookalike domain in URL": (
        "A link appears to use a lookalike or impersonation domain.",
        P_BRAND,
    ),
    "URL uses an IP address instead of a domain": (
        "A link uses an IP address instead of a normal domain.",
        P_URL_DESTINATION,
    ),
    "URL contains an @ symbol that may obscure the destination": (
        "A link contains an @ symbol, which can hide the actual destination.",
        P_URL_DESTINATION,
    ),
    "URL uses a punycode domain": (
        "A link uses punycode, which can be associated with lookalike domains.",
        P_URL_DESTINATION,
    ),
    "Link text does not match the actual destination": (
        "The visible link text does not match its actual destination.",
        P_URL_DESTINATION,
    ),
    "URL does not use HTTPS": ("A link does not use HTTPS.", P_MINOR),
    "URL contains security-sensitive keywords": (
        "A link contains keywords commonly associated with account or credential actions.",
        P_MINOR,
    ),
    "URL contains an unusually deep subdomain structure": (
        "A link uses an unusually deep subdomain structure.",
        P_MINOR,
    ),
    "URL uses a potentially suspicious top-level domain": (
        "A link uses a top-level domain that is sometimes associated with phishing.",
        P_MINOR,
    ),
    "URL is unusually long": ("A link is unusually long.", P_MINOR),
    "URL has an unusually deep path": ("A link contains an unusually deep path.", P_MINOR),
    "URL has an unusual structure": ("A link has an unusual URL structure.", P_MINOR),
    # Content
    "Email requests sensitive account credentials": (
        "The email asks for sensitive account credentials.",
        P_CREDENTIAL_OTP,
    ),
    "Email requests a security or verification code": (
        "The email asks for a security code or one-time password.",
        P_CREDENTIAL_OTP,
    ),
    "Email requests payment or sensitive financial information": (
        "The email requests payment or financial information.",
        P_PAYMENT,
    ),
    "Email requests account or identity verification": (
        "The email asks the recipient to verify an account or identity.",
        P_VERIFICATION,
    ),
    "Email uses strong urgency or threat language": (
        "The email uses urgency or threat language to pressure the recipient.",
        P_URGENCY,
    ),
    "Email contains a suspicious call to action": (
        "The email uses a suspicious call to action.",
        P_MINOR,
    ),
    "Email uses language associated with a known brand or service": (
        "The email uses language associated with a known brand or service.",
        P_MINOR,
    ),
    "Email uses a generic recipient greeting": (
        "The email uses a generic recipient greeting.",
        P_GREETING,
    ),
}

BRAND_IN_URL_STRONG_TEXT = "A link appears to use a lookalike or impersonation domain."
BRAND_IN_URL_WEAK_TEXT = "A known brand name appears in a suspicious link."


def _describe(item: Evidence) -> tuple[str, int]:
    """Return (explanation text, priority) for one evidence item; never raises."""
    if item.reason == BRAND_IN_URL_REASON:
        if item.severity >= BRAND_IN_URL_STRONG_MIN_SEVERITY:
            return BRAND_IN_URL_STRONG_TEXT, P_BRAND
        return BRAND_IN_URL_WEAK_TEXT, P_MINOR
    known = REASON_EXPLANATIONS.get(item.reason)
    if known:
        return known
    return (item.reason.strip() or GENERIC_FALLBACK), DEFAULT_PRIORITY


def _shorten(value: str | None) -> str | None:
    if value is None:
        return None
    value = " ".join(value.split())
    if not value:
        return None
    if len(value) > MAX_OBSERVED_LENGTH:
        return value[: MAX_OBSERVED_LENGTH - 3] + "..."
    return value


def _select_reasons(evidence: list[Evidence]) -> list[ExplanationReason]:
    described = [(*_describe(item), item, index) for index, item in enumerate(evidence)]
    # Most important first: priority, then higher severity, then original order.
    described.sort(key=lambda entry: (entry[1], -entry[2].severity, entry[3]))

    reasons: list[ExplanationReason] = []
    seen: set[tuple[str, str]] = set()
    for text, _priority, item, _index in described:
        key = (item.category, text)
        if key in seen:  # same finding repeated (e.g. on several links): show it once
            continue
        seen.add(key)
        reasons.append(
            ExplanationReason(
                reason=text,
                severity=item.severity,
                category=item.category,
                observed_value=_shorten(item.observed_value),
            )
        )
        if len(reasons) == MAX_REASONS:
            break
    return reasons


def generate_explanation(evidence: list[Evidence], risk_result: RiskResult) -> ExplanationResult:
    """Explain an existing RiskResult using only the evidence that produced it."""
    return ExplanationResult(
        verdict=risk_result.verdict,
        risk_score=risk_result.risk_score,
        confidence=risk_result.confidence,
        summary=SUMMARIES[risk_result.verdict],
        reasons=_select_reasons(evidence),
        recommended_action=RECOMMENDED_ACTIONS[risk_result.verdict],
        evidence_count=risk_result.evidence_count,
        categories_detected=list(risk_result.categories_detected),
    )
