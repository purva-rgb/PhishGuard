"""Deterministic MVP evidence fusion and risk scoring.

Evidence.severity is NOT used as a probability. Each distinct evidence reason maps to a
hand-chosen contribution; contributions are summed per signal family, capped per family, and a
small bonus is added when independent families agree. The numbers below are heuristic MVP
weights, not statistically calibrated values.
"""

from app.schemas.evidence import Evidence
from app.schemas.risk import RiskResult

# --- Signal families -----------------------------------------------------------------------------

HEADER = "HEADER"
URL = "URL"
CONTENT = "CONTENT"

# Evidence.category -> signal family. URL, DOMAIN and BRAND evidence describe the same links,
# so they form one family rather than independent ones.
CATEGORY_FAMILY: dict[str, str] = {
    "HEADER": HEADER,
    "AUTHENTICATION": HEADER,
    "URL": URL,
    "DOMAIN": URL,
    "BRAND": URL,
    "CONTENT": CONTENT,
}

FAMILY_CAPS: dict[str, float] = {HEADER: 0.40, URL: 0.55, CONTENT: 0.35}

# --- Contributions per evidence reason (as produced by the Part 3-5 analyzers) -------------------

REASON_CONTRIBUTIONS: dict[str, float] = {
    # Header / authentication
    "DMARC authentication failed": 0.20,
    "SPF authentication failed": 0.15,
    "DKIM authentication failed": 0.15,
    "Reply-To domain differs from sender domain": 0.15,
    "Return-Path domain differs from sender domain": 0.12,
    "Display name may impersonate a known brand": 0.15,
    "Sender domain is an IP address": 0.10,
    "Sender domain uses punycode (xn--)": 0.08,
    "Sender domain is missing or invalid": 0.05,
    "Message-ID domain differs from sender domain": 0.03,
    # URL / domain / brand
    "URL contains an @ symbol that may obscure the destination": 0.20,
    "URL uses an IP address instead of a domain": 0.20,
    "Link text does not match the actual destination": 0.20,
    "URL uses a punycode domain": 0.15,
    "Possible brand lookalike domain in URL": 0.25,
    "URL contains an unusually deep subdomain structure": 0.05,
    "URL uses a potentially suspicious top-level domain": 0.05,
    "URL contains security-sensitive keywords": 0.05,
    "URL has an unusual structure": 0.05,
    "URL is unusually long": 0.03,
    "URL has an unusually deep path": 0.03,
    "URL does not use HTTPS": 0.02,
    # Content
    "Email requests sensitive account credentials": 0.15,
    "Email requests a security or verification code": 0.15,
    "Email requests payment or sensitive financial information": 0.15,
    "Email requests account or identity verification": 0.10,
    "Email uses strong urgency or threat language": 0.10,
    "Email contains a suspicious call to action": 0.05,
    "Email uses language associated with a known brand or service": 0.05,
    "Email uses a generic recipient greeting": 0.01,
}

# "Possible brand impersonation in URL" is emitted at two strengths by the brand analyzer:
# hostname match (severity 0.85) is strong, a path-only mention (severity 0.5) is weak.
BRAND_IN_URL_REASON = "Possible brand impersonation in URL"
BRAND_IN_URL_STRONG = 0.25
BRAND_IN_URL_WEAK = 0.08
BRAND_IN_URL_STRONG_MIN_SEVERITY = 0.7

# Threat intelligence is not implemented: no Evidence reason for it exists yet. When one is added,
# give it an entry in REASON_CONTRIBUTIONS (or a hard-malicious rule) here.

# --- Multi-signal bonus, thresholds, confidence --------------------------------------------------

MEANINGFUL_CONTRIBUTION = 0.05  # a reason / family below this is too weak to count as diversity
STRONG_CONTRIBUTION = 0.15  # a "strong" indicator for confidence purposes
MULTI_SIGNAL_BONUS = {2: 0.05, 3: 0.10}

SUSPICIOUS_THRESHOLD = 0.30
MALICIOUS_THRESHOLD = 0.70


def clamp_score(score: float) -> float:
    return max(0.0, min(1.0, score))


def verdict_for_score(score: float) -> str:
    """SAFE < 0.30 <= SUSPICIOUS < 0.70 <= MALICIOUS (score is rounded to 2 decimals first)."""
    score = round(clamp_score(score), 2)
    if score >= MALICIOUS_THRESHOLD:
        return "MALICIOUS"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "SAFE"


def _contribution(item: Evidence) -> float:
    if item.reason == BRAND_IN_URL_REASON:
        if item.severity >= BRAND_IN_URL_STRONG_MIN_SEVERITY:
            return BRAND_IN_URL_STRONG
        return BRAND_IN_URL_WEAK
    return REASON_CONTRIBUTIONS.get(item.reason, 0.0)


def _distinct_reason_contributions(evidence: list[Evidence]) -> dict[tuple[str, str], float]:
    """One contribution per (family, reason): repeated evidence with the same reason counts once."""
    contributions: dict[tuple[str, str], float] = {}
    for item in evidence:
        family = CATEGORY_FAMILY.get(item.category)
        if family is None:
            continue
        key = (family, item.reason)
        contributions[key] = max(contributions.get(key, 0.0), _contribution(item))
    return contributions


def _confidence(
    evidence_count: int,
    meaningful_families: int,
    meaningful_reasons: int,
    strong_reasons: int,
) -> str:
    if evidence_count == 0:
        return "LOW"
    if (meaningful_families >= 3 and strong_reasons >= 1) or strong_reasons >= 3:
        return "HIGH"
    if meaningful_families >= 2 or meaningful_reasons >= 2:
        return "MEDIUM"
    return "LOW"


def calculate_risk(evidence: list[Evidence]) -> RiskResult:
    """Fuse independent evidence into a risk score, verdict and heuristic confidence."""
    distinct = _distinct_reason_contributions(evidence)

    family_totals: dict[str, float] = {}
    for (family, _reason), contribution in distinct.items():
        family_totals[family] = family_totals.get(family, 0.0) + contribution
    capped_totals = {
        family: min(total, FAMILY_CAPS[family]) for family, total in family_totals.items()
    }

    meaningful_families = [
        family for family, total in capped_totals.items() if total >= MEANINGFUL_CONTRIBUTION
    ]
    bonus = MULTI_SIGNAL_BONUS.get(min(len(meaningful_families), 3), 0.0)

    score = round(clamp_score(sum(capped_totals.values()) + bonus), 2)

    meaningful_reasons = sum(1 for value in distinct.values() if value >= MEANINGFUL_CONTRIBUTION)
    strong_reasons = sum(1 for value in distinct.values() if value >= STRONG_CONTRIBUTION)

    return RiskResult(
        risk_score=score,
        verdict=verdict_for_score(score),
        confidence=_confidence(
            len(evidence), len(meaningful_families), meaningful_reasons, strong_reasons
        ),
        evidence_count=len(evidence),
        categories_detected=sorted({item.category for item in evidence}),
        signal_families=sorted(meaningful_families),
    )
