import json
from pathlib import Path

import pytest

from app.analysis.content_analyzer import analyze_content
from app.analysis.explanation_engine import (
    BRAND_IN_URL_STRONG_TEXT,
    BRAND_IN_URL_WEAK_TEXT,
    GENERIC_FALLBACK,
    MAX_OBSERVED_LENGTH,
    MAX_REASONS,
    REASON_EXPLANATIONS,
    generate_explanation,
)
from app.analysis.header_analyzer import analyze_headers
from app.analysis.risk_engine import BRAND_IN_URL_REASON, REASON_CONTRIBUTIONS, calculate_risk
from app.analysis.url_analyzer import build_url_analysis
from app.preprocessing.email_parser import parse_email
from app.preprocessing.url_extractor import extract_urls
from app.schemas.evidence import Evidence
from app.schemas.explanation import ExplanationResult
from app.schemas.risk import RiskResult

BACKEND_DIR = Path(__file__).resolve().parent.parent


def ev(category: str, reason: str, severity: float = 0.5, observed: str | None = None) -> Evidence:
    return Evidence(
        category=category, severity=severity, reason=reason, observed_value=observed, source="test"
    )


def risk_result(verdict: str, score: float, confidence: str = "MEDIUM", count: int = 1) -> RiskResult:
    return RiskResult(
        risk_score=score,
        verdict=verdict,
        confidence=confidence,
        evidence_count=count,
        categories_detected=["HEADER"],
        signal_families=["HEADER"],
    )


def explain_one(category: str, reason: str, severity: float = 0.5, observed=None) -> ExplanationResult:
    item = ev(category, reason, severity, observed)
    return generate_explanation([item], calculate_risk([item]))


def texts(result: ExplanationResult) -> list[str]:
    return [reason.reason for reason in result.reasons]


# --- Summary and recommended action ----------------------------------------------------------


def test_malicious_summary_and_action():
    result = generate_explanation([], risk_result("MALICIOUS", 0.85, "HIGH"))
    assert result.summary == "Multiple strong phishing indicators were detected."
    assert result.recommended_action == (
        "Do not click links or provide credentials. Verify the sender through an independent "
        "trusted channel and report the email."
    )


def test_suspicious_summary_and_action():
    result = generate_explanation([], risk_result("SUSPICIOUS", 0.45))
    assert result.summary == "Some phishing indicators were detected, but the evidence is not conclusive."
    assert result.recommended_action == (
        "Do not click links or provide sensitive information until the sender and request are "
        "independently verified."
    )


def test_safe_summary_and_action_do_not_claim_certainty():
    result = generate_explanation([], risk_result("SAFE", 0.05, "LOW"))
    assert result.summary.startswith("No major phishing indicators were detected.")
    assert result.recommended_action == (
        "No major phishing indicators were detected. Still verify unexpected requests before "
        "taking action."
    )
    combined = (result.summary + result.recommended_action).lower()
    assert "definitely" not in combined
    assert "guaranteed safe" not in combined
    assert "does not guarantee" in combined


# --- Header / authentication mappings --------------------------------------------------------


def test_reply_to_mapping_with_observed_value():
    result = explain_one(
        "HEADER",
        "Reply-To domain differs from sender domain",
        0.8,
        "security@example.com -> verify@randommail.xyz",
    )
    reason = result.reasons[0]
    assert reason.reason == "The Reply-To address uses a different domain from the sender."
    assert reason.category == "HEADER"
    assert reason.severity == 0.8
    assert reason.observed_value == "security@example.com -> verify@randommail.xyz"


def test_return_path_mapping():
    result = explain_one("HEADER", "Return-Path domain differs from sender domain", 0.7)
    assert texts(result) == ["The return address uses a different domain from the sender."]


def test_spf_failure_mapping():
    result = explain_one("AUTHENTICATION", "SPF authentication failed", 0.9, "spf=fail")
    assert texts(result) == ["The sender failed SPF email authentication."]
    assert result.reasons[0].category == "AUTHENTICATION"


def test_dkim_failure_mapping():
    assert texts(explain_one("AUTHENTICATION", "DKIM authentication failed", 0.8)) == [
        "The sender failed DKIM email authentication."
    ]


def test_dmarc_failure_mapping():
    assert texts(explain_one("AUTHENTICATION", "DMARC authentication failed", 0.95)) == [
        "The sender failed DMARC email authentication."
    ]


@pytest.mark.parametrize(
    "reason, expected",
    [
        (
            "Display name may impersonate a known brand",
            "The sender's display name appears to impersonate a known brand.",
        ),
        ("Sender domain is an IP address", "The sender uses an IP address instead of a normal domain."),
        (
            "Sender domain uses punycode (xn--)",
            "The sender domain uses punycode, which can be associated with lookalike domains.",
        ),
        (
            "Message-ID domain differs from sender domain",
            "The message ID domain differs from the sender domain.",
        ),
    ],
)
def test_other_header_mappings(reason, expected):
    assert texts(explain_one("HEADER", reason)) == [expected]


# --- URL / domain / brand mappings -----------------------------------------------------------


def test_url_ip_mapping():
    result = explain_one("URL", "URL uses an IP address instead of a domain", 0.8, "192.168.1.10")
    assert texts(result) == ["A link uses an IP address instead of a normal domain."]
    assert result.reasons[0].observed_value == "192.168.1.10"


def test_url_punycode_mapping():
    assert texts(explain_one("URL", "URL uses a punycode domain", 0.7)) == [
        "A link uses punycode, which can be associated with lookalike domains."
    ]


def test_url_at_symbol_mapping():
    result = explain_one("URL", "URL contains an @ symbol that may obscure the destination", 0.9)
    assert texts(result) == ["A link contains an @ symbol, which can hide the actual destination."]


@pytest.mark.parametrize(
    "category, reason, expected",
    [
        ("URL", "URL does not use HTTPS", "A link does not use HTTPS."),
        (
            "URL",
            "URL contains security-sensitive keywords",
            "A link contains keywords commonly associated with account or credential actions.",
        ),
        (
            "DOMAIN",
            "URL contains an unusually deep subdomain structure",
            "A link uses an unusually deep subdomain structure.",
        ),
        ("URL", "URL is unusually long", "A link is unusually long."),
        ("URL", "URL has an unusually deep path", "A link contains an unusually deep path."),
        ("URL", "URL has an unusual structure", "A link has an unusual URL structure."),
        (
            "DOMAIN",
            "URL uses a potentially suspicious top-level domain",
            "A link uses a top-level domain that is sometimes associated with phishing.",
        ),
    ],
)
def test_suspicious_url_structure_mappings(category, reason, expected):
    assert texts(explain_one(category, reason)) == [expected]


def test_anchor_href_mismatch_mapping():
    result = explain_one(
        "URL", "Link text does not match the actual destination", 0.85, "PayPal Login -> evil.xyz"
    )
    assert texts(result) == ["The visible link text does not match its actual destination."]
    assert result.reasons[0].observed_value == "PayPal Login -> evil.xyz"


def test_brand_lookalike_mapping():
    result = explain_one("BRAND", "Possible brand lookalike domain in URL", 0.9, "paypa1 resembles paypal")
    assert texts(result) == ["A link appears to use a lookalike or impersonation domain."]


def test_brand_in_url_depends_on_strength():
    strong = explain_one("BRAND", BRAND_IN_URL_REASON, 0.85)
    weak = explain_one("BRAND", BRAND_IN_URL_REASON, 0.5)
    assert texts(strong) == [BRAND_IN_URL_STRONG_TEXT]
    assert texts(weak) == [BRAND_IN_URL_WEAK_TEXT] == ["A known brand name appears in a suspicious link."]


# --- Content mappings ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason, expected",
    [
        ("Email requests sensitive account credentials", "The email asks for sensitive account credentials."),
        (
            "Email requests a security or verification code",
            "The email asks for a security code or one-time password.",
        ),
        (
            "Email requests account or identity verification",
            "The email asks the recipient to verify an account or identity.",
        ),
        (
            "Email requests payment or sensitive financial information",
            "The email requests payment or financial information.",
        ),
        (
            "Email uses strong urgency or threat language",
            "The email uses urgency or threat language to pressure the recipient.",
        ),
        ("Email contains a suspicious call to action", "The email uses a suspicious call to action."),
        (
            "Email uses language associated with a known brand or service",
            "The email uses language associated with a known brand or service.",
        ),
        ("Email uses a generic recipient greeting", "The email uses a generic recipient greeting."),
    ],
)
def test_content_mappings(reason, expected):
    result = explain_one("CONTENT", reason)
    assert texts(result) == [expected]
    assert result.reasons[0].category == "CONTENT"


def test_every_reason_the_risk_engine_knows_has_an_explanation():
    for reason in REASON_CONTRIBUTIONS:
        assert reason in REASON_EXPLANATIONS, f"no explanation mapping for '{reason}'"
    assert BRAND_IN_URL_REASON not in REASON_EXPLANATIONS  # handled by severity-based branch


# --- Unknown evidence ------------------------------------------------------------------------


def test_unknown_reason_does_not_crash_and_uses_original_text():
    result = explain_one("THREAT_INTEL", "Domain listed on a future blocklist", 0.9, "evil.example")
    assert texts(result) == ["Domain listed on a future blocklist"]
    assert result.reasons[0].category == "THREAT_INTEL"
    assert result.reasons[0].observed_value == "evil.example"


def test_blank_unknown_reason_gets_generic_fallback():
    result = generate_explanation([ev("OTHER", "   ")], risk_result("SAFE", 0.0))
    assert texts(result) == [GENERIC_FALLBACK]


def test_unknown_reason_is_not_given_an_invented_explanation():
    result = explain_one("CONTENT", "Something brand new")
    assert "phishing" not in texts(result)[0].lower()
    assert texts(result) == ["Something brand new"]


# --- Ranking and limits ----------------------------------------------------------------------


def full_evidence() -> list[Evidence]:
    # Deliberately in "wrong" order.
    return [
        ev("CONTENT", "Email uses a generic recipient greeting", 0.15),
        ev("CONTENT", "Email contains a suspicious call to action", 0.35),
        ev("CONTENT", "Email uses strong urgency or threat language", 0.5),
        ev("CONTENT", "Email requests account or identity verification", 0.5),
        ev("CONTENT", "Email requests payment or sensitive financial information", 0.7),
        ev("CONTENT", "Email requests sensitive account credentials", 0.8),
        ev("HEADER", "Reply-To domain differs from sender domain", 0.8),
        ev("URL", "URL uses an IP address instead of a domain", 0.8),
        ev("BRAND", "Possible brand lookalike domain in URL", 0.9),
        ev("AUTHENTICATION", "DKIM authentication failed", 0.8),
        ev("AUTHENTICATION", "SPF authentication failed", 0.9),
        ev("AUTHENTICATION", "DMARC authentication failed", 0.95),
    ]


def test_reasons_are_ranked_by_importance():
    evidence = [
        ev("CONTENT", "Email uses a generic recipient greeting", 0.15),
        ev("CONTENT", "Email contains a suspicious call to action", 0.35),
        ev("CONTENT", "Email uses strong urgency or threat language", 0.5),
        ev("CONTENT", "Email requests account or identity verification", 0.5),
        ev("CONTENT", "Email requests payment or sensitive financial information", 0.7),
    ]
    result = generate_explanation(evidence, calculate_risk(evidence))
    assert texts(result) == [
        "The email requests payment or financial information.",
        "The email asks the recipient to verify an account or identity.",
        "The email uses urgency or threat language to pressure the recipient.",
        "The email uses a suspicious call to action.",
        "The email uses a generic recipient greeting.",
    ]


def test_priority_order_across_categories_and_severity_within_priority():
    evidence = full_evidence()
    result = generate_explanation(evidence, calculate_risk(evidence))
    assert texts(result) == [
        "The sender failed DMARC email authentication.",  # authentication, highest severity
        "The sender failed SPF email authentication.",
        "The sender failed DKIM email authentication.",
        "A link appears to use a lookalike or impersonation domain.",  # brand
        "A link uses an IP address instead of a normal domain.",  # URL destination
    ]


def test_at_most_five_reasons_and_evidence_is_untouched():
    evidence = full_evidence()
    snapshot = [item.model_copy(deep=True) for item in evidence]
    result = generate_explanation(evidence, calculate_risk(evidence))
    assert len(result.reasons) == MAX_REASONS == 5
    assert evidence == snapshot
    assert len(evidence) == 12
    assert result.evidence_count == 12  # reported from RiskResult, not the truncated list


def test_equal_priority_and_severity_keeps_input_order():
    evidence = [
        ev("URL", "URL is unusually long", 0.5),
        ev("URL", "URL has an unusually deep path", 0.5),
        ev("URL", "URL does not use HTTPS", 0.5),
    ]
    result = generate_explanation(evidence, calculate_risk(evidence))
    assert texts(result) == [
        "A link is unusually long.",
        "A link contains an unusually deep path.",
        "A link does not use HTTPS.",
    ]


def test_same_finding_on_several_links_is_shown_once_with_highest_severity():
    evidence = [
        ev("URL", "URL uses an IP address instead of a domain", 0.6, "10.0.0.1"),
        ev("URL", "URL uses an IP address instead of a domain", 0.8, "192.168.1.10"),
    ]
    result = generate_explanation(evidence, calculate_risk(evidence))
    assert len(result.reasons) == 1
    assert result.reasons[0].severity == 0.8
    assert result.reasons[0].observed_value == "192.168.1.10"


# --- Observed values -------------------------------------------------------------------------


def test_long_observed_values_are_truncated_without_touching_evidence():
    long_value = "http://example.xyz/" + "a" * 500
    item = ev("URL", "URL is unusually long", 0.5, long_value)
    result = generate_explanation([item], calculate_risk([item]))
    shown = result.reasons[0].observed_value
    assert len(shown) == MAX_OBSERVED_LENGTH == 120
    assert shown.endswith("...")
    assert shown.startswith("http://example.xyz/")
    assert item.observed_value == long_value


def test_short_and_missing_observed_values():
    assert explain_one("URL", "URL does not use HTTPS", 0.3, "http://example.xyz/login").reasons[
        0
    ].observed_value == "http://example.xyz/login"
    assert explain_one("URL", "URL does not use HTTPS", 0.3, None).reasons[0].observed_value is None
    assert explain_one("URL", "URL does not use HTTPS", 0.3, "   ").reasons[0].observed_value is None


def test_observed_value_whitespace_is_collapsed():
    result = explain_one("URL", "URL does not use HTTPS", 0.3, "a  \n b")
    assert result.reasons[0].observed_value == "a b"


# --- Empty evidence --------------------------------------------------------------------------


def test_empty_evidence():
    result = generate_explanation([], calculate_risk([]))
    assert result.reasons == []
    assert result.verdict == "SAFE"
    assert result.risk_score == 0.0
    assert result.confidence == "LOW"
    assert result.evidence_count == 0
    assert result.summary
    assert result.recommended_action


# --- No new scoring --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "verdict, score, confidence",
    [
        ("MALICIOUS", 0.85, "HIGH"),
        ("SUSPICIOUS", 0.55, "MEDIUM"),
        ("SAFE", 0.12, "LOW"),
        ("MALICIOUS", 0.7, "LOW"),  # preserved even if it looks inconsistent with the evidence
    ],
)
def test_score_verdict_and_confidence_are_preserved_exactly(verdict, score, confidence):
    evidence = full_evidence()
    result = generate_explanation(evidence, risk_result(verdict, score, confidence, len(evidence)))
    assert result.risk_score == score
    assert result.verdict == verdict
    assert result.confidence == confidence


def test_explanation_preserves_calculated_risk_values():
    evidence = full_evidence()
    calculated = calculate_risk(evidence)
    snapshot = calculated.model_copy(deep=True)
    result = generate_explanation(evidence, calculated)
    assert (result.risk_score, result.verdict, result.confidence) == (
        calculated.risk_score,
        calculated.verdict,
        calculated.confidence,
    )
    assert result.categories_detected == calculated.categories_detected
    assert calculated == snapshot


def test_explanation_does_not_alter_inputs():
    evidence = full_evidence()
    calculated = calculate_risk(evidence)
    evidence_before = [item.model_copy(deep=True) for item in evidence]
    generate_explanation(evidence, calculated)
    assert evidence == evidence_before


# --- Combined / end-to-end -------------------------------------------------------------------


def test_multiple_categories_produce_useful_combined_reasons():
    evidence = [
        ev("AUTHENTICATION", "SPF authentication failed", 0.9),
        ev("HEADER", "Reply-To domain differs from sender domain", 0.8, "a@x.com -> b@y.net"),
        ev("URL", "Link text does not match the actual destination", 0.85, "PayPal -> evil.xyz"),
        ev("CONTENT", "Email requests sensitive account credentials", 0.8, "enter your password"),
    ]
    result = generate_explanation(evidence, calculate_risk(evidence))
    assert {reason.category for reason in result.reasons} == {
        "AUTHENTICATION", "HEADER", "URL", "CONTENT",
    }
    assert texts(result) == [
        "The sender failed SPF email authentication.",
        "The visible link text does not match its actual destination.",
        "The Reply-To address uses a different domain from the sender.",
        "The email asks for sensitive account credentials.",
    ]
    assert set(result.categories_detected) == {"AUTHENTICATION", "HEADER", "URL", "CONTENT"}


def test_end_to_end_with_real_analyzers():
    raw = json.loads((BACKEND_DIR / "sample_request.json").read_text(encoding="utf-8"))["email_text"]
    parsed = parse_email(raw)
    evidence = analyze_headers(parsed) + analyze_content(parsed)
    for extracted in extract_urls(parsed):
        evidence += build_url_analysis(extracted).evidence

    calculated = calculate_risk(evidence)
    result = generate_explanation(evidence, calculated)

    assert result.verdict == calculated.verdict == "MALICIOUS"
    assert result.risk_score == calculated.risk_score
    assert 1 <= len(result.reasons) <= 5
    assert result.reasons[0].reason == "The sender failed DMARC email authentication."
    assert all(reason.reason for reason in result.reasons)
    known_texts = {text for text, _ in REASON_EXPLANATIONS.values()} | {
        BRAND_IN_URL_STRONG_TEXT, BRAND_IN_URL_WEAK_TEXT,
    }
    assert all(reason.reason in known_texts for reason in result.reasons)


# --- Determinism -----------------------------------------------------------------------------


def test_output_is_deterministic():
    evidence = full_evidence()
    calculated = calculate_risk(evidence)
    first = generate_explanation(evidence, calculated)
    second = generate_explanation(evidence, calculated)
    third = generate_explanation(list(evidence), calculated.model_copy())
    assert first == second == third
    assert first.model_dump_json() == second.model_dump_json()
