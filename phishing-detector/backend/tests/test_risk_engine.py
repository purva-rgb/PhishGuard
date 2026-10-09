import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.analysis import risk_engine
from app.analysis.content_analyzer import analyze_content
from app.analysis.header_analyzer import analyze_headers
from app.analysis.risk_engine import (
    BRAND_IN_URL_REASON,
    REASON_CONTRIBUTIONS,
    calculate_risk,
    clamp_score,
    verdict_for_score,
)
from app.analysis.url_analyzer import build_url_analysis
from app.preprocessing.email_parser import parse_email
from app.preprocessing.url_extractor import extract_urls
from app.schemas.evidence import Evidence
from app.schemas.risk import RiskResult

BACKEND_DIR = Path(__file__).resolve().parent.parent

# Reason strings produced by the Part 3-5 analyzers.
DMARC = ("AUTHENTICATION", "DMARC authentication failed")
SPF = ("AUTHENTICATION", "SPF authentication failed")
DKIM = ("AUTHENTICATION", "DKIM authentication failed")
REPLY_TO = ("HEADER", "Reply-To domain differs from sender domain")
RETURN_PATH = ("HEADER", "Return-Path domain differs from sender domain")
DISPLAY_NAME = ("HEADER", "Display name may impersonate a known brand")
MESSAGE_ID = ("HEADER", "Message-ID domain differs from sender domain")

URL_IP = ("URL", "URL uses an IP address instead of a domain")
URL_AT = ("URL", "URL contains an @ symbol that may obscure the destination")
URL_PUNYCODE = ("URL", "URL uses a punycode domain")
URL_ANCHOR = ("URL", "Link text does not match the actual destination")
URL_HTTP = ("URL", "URL does not use HTTPS")
URL_KEYWORDS = ("URL", "URL contains security-sensitive keywords")
URL_LONG = ("URL", "URL is unusually long")
URL_DEEP_PATH = ("URL", "URL has an unusually deep path")
DOMAIN_TLD = ("DOMAIN", "URL uses a potentially suspicious top-level domain")
DOMAIN_SUBDOMAINS = ("DOMAIN", "URL contains an unusually deep subdomain structure")
BRAND_LOOKALIKE = ("BRAND", "Possible brand lookalike domain in URL")

CREDENTIALS = ("CONTENT", "Email requests sensitive account credentials")
OTP = ("CONTENT", "Email requests a security or verification code")
VERIFICATION = ("CONTENT", "Email requests account or identity verification")
PAYMENT = ("CONTENT", "Email requests payment or sensitive financial information")
URGENCY = ("CONTENT", "Email uses strong urgency or threat language")
CTA = ("CONTENT", "Email contains a suspicious call to action")
BRAND_LANGUAGE = ("CONTENT", "Email uses language associated with a known brand or service")
GREETING = ("CONTENT", "Email uses a generic recipient greeting")


def ev(signal: tuple[str, str], severity: float = 0.5) -> Evidence:
    category, reason = signal
    return Evidence(category=category, severity=severity, reason=reason, source="test")


def brand_in_url(severity: float) -> Evidence:
    return Evidence(
        category="BRAND", severity=severity, reason=BRAND_IN_URL_REASON, source="brand_analyzer"
    )


def risk(*signals) -> RiskResult:
    return calculate_risk([ev(signal) for signal in signals])


# --- Basic cases ---------------------------------------------------------------------------


def test_empty_evidence():
    result = calculate_risk([])
    assert result.risk_score == 0.0
    assert result.verdict == "SAFE"
    assert result.confidence == "LOW"
    assert result.evidence_count == 0
    assert result.categories_detected == []
    assert result.signal_families == []


def test_generic_greeting_only_is_safe():
    result = risk(GREETING)
    assert result.risk_score == 0.01
    assert result.verdict == "SAFE"
    assert result.confidence == "LOW"


def test_one_weak_cta_is_safe():
    result = risk(CTA)
    assert result.risk_score == 0.05
    assert result.verdict == "SAFE"
    assert result.confidence == "LOW"


def test_one_credential_request_is_not_malicious():
    result = risk(CREDENTIALS)
    assert result.risk_score == 0.15
    assert result.verdict != "MALICIOUS"
    assert result.confidence == "LOW"


def test_one_otp_request_is_not_malicious():
    assert risk(OTP).verdict != "MALICIOUS"


def test_one_urgency_signal_is_not_malicious():
    result = risk(URGENCY)
    assert result.risk_score == 0.10
    assert result.verdict != "MALICIOUS"


def test_one_brand_mention_is_not_malicious():
    assert risk(BRAND_LANGUAGE).verdict == "SAFE"


def test_verification_plus_code_request_is_not_malicious():
    # "Your account requires verification. Enter your verification code."
    body = "Your account requires verification. Enter your verification code."
    from app.schemas.parsed_email import ParsedEmail

    result = calculate_risk(analyze_content(ParsedEmail(plain_text_body=body)))
    assert result.verdict != "MALICIOUS"
    assert result.evidence_count >= 2


def test_multiple_content_signals_increase_risk():
    single = risk(CREDENTIALS)
    several = risk(CREDENTIALS, URGENCY, VERIFICATION)
    assert several.risk_score > single.risk_score
    assert several.risk_score == 0.35  # 0.15 + 0.10 + 0.10 = 0.35 (equals the content cap)
    assert several.verdict == "SUSPICIOUS"


# --- Multi-signal bonus --------------------------------------------------------------------


def test_header_plus_content_gets_two_family_bonus():
    result = risk(SPF, CREDENTIALS)
    assert result.risk_score == 0.35  # 0.15 + 0.15 + 0.05 bonus
    assert result.signal_families == ["CONTENT", "HEADER"]


def test_header_url_content_gets_three_family_bonus():
    result = risk(SPF, URL_IP, CREDENTIALS)
    assert result.risk_score == 0.60  # 0.15 + 0.20 + 0.15 + 0.10 bonus
    assert result.risk_score > risk(SPF, CREDENTIALS).risk_score


def test_bonus_is_not_repeated_for_more_families_or_evidence():
    result = risk(SPF, DKIM, URL_IP, URL_AT, CREDENTIALS, OTP)
    # header 0.30 + url 0.40 + content 0.30 + 0.10 bonus (applied once) = 1.10, clamped to 1.0
    assert result.risk_score == 1.0
    assert result.signal_families == ["CONTENT", "HEADER", "URL"]


def test_url_and_brand_are_one_family_with_no_bonus():
    result = risk(URL_IP, BRAND_LOOKALIKE)
    assert result.signal_families == ["URL"]
    assert result.risk_score == 0.45  # 0.20 + 0.25, no multi-signal bonus
    assert set(result.categories_detected) == {"URL", "BRAND"}


def test_trivial_signals_do_not_earn_the_bonus():
    result = risk(SPF, GREETING)  # greeting alone is far below the meaningful threshold
    assert result.risk_score == 0.16
    assert result.signal_families == ["HEADER"]


# --- Higher-risk combinations --------------------------------------------------------------


def test_strong_brand_lookalike_plus_suspicious_urls_is_high_risk():
    result = risk(BRAND_LOOKALIKE, URL_IP, URL_AT)
    assert result.risk_score == 0.55  # 0.25 + 0.20 + 0.20 = 0.65 raw, capped at the URL family cap
    assert result.verdict == "SUSPICIOUS"
    assert result.risk_score > risk(BRAND_LOOKALIKE).risk_score


def test_brand_in_url_strength_depends_on_severity():
    strong = calculate_risk([brand_in_url(0.85)])
    weak = calculate_risk([brand_in_url(0.5)])
    assert strong.risk_score == 0.25
    assert weak.risk_score == 0.08


def test_dmarc_fail_reply_to_and_credentials_is_high_risk():
    result = risk(DMARC, REPLY_TO, CREDENTIALS)
    # header 0.20 + 0.15 = 0.35, content 0.15, bonus 0.05
    assert result.risk_score == 0.55
    assert result.verdict == "SUSPICIOUS"  # the specified weights do not reach 0.70 on their own
    assert result.risk_score > risk(DMARC, REPLY_TO).risk_score


def test_agreement_across_three_families_can_be_malicious():
    result = risk(DMARC, REPLY_TO, BRAND_LOOKALIKE, CREDENTIALS)
    # header 0.35 + url 0.25 + content 0.15 + bonus 0.10
    assert result.risk_score == 0.85
    assert result.verdict == "MALICIOUS"
    assert result.confidence == "HIGH"


# --- Family caps and duplicate control -----------------------------------------------------


def test_repeated_credential_evidence_is_not_inflated():
    one = calculate_risk([ev(CREDENTIALS)])
    many = calculate_risk([ev(CREDENTIALS) for _ in range(10)])
    assert many.risk_score == one.risk_score == 0.15
    assert many.evidence_count == 10


def test_repeated_urgency_evidence_is_not_inflated():
    assert calculate_risk([ev(URGENCY) for _ in range(5)]).risk_score == 0.10


def test_url_evidence_from_many_urls_counts_once_per_reason():
    result = calculate_risk([ev(URL_IP) for _ in range(6)])
    assert result.risk_score == 0.20


def test_url_family_cap():
    result = risk(URL_IP, URL_AT, URL_ANCHOR, URL_PUNYCODE, BRAND_LOOKALIKE)
    assert result.risk_score == 0.55  # 1.00 raw, capped at 0.55
    assert result.signal_families == ["URL"]


def test_header_family_cap():
    result = risk(DMARC, SPF, DKIM, REPLY_TO, RETURN_PATH)
    assert result.risk_score == 0.40  # 0.77 raw, capped at 0.40


def test_content_family_cap():
    result = risk(CREDENTIALS, OTP, PAYMENT, VERIFICATION, URGENCY, CTA, BRAND_LANGUAGE)
    assert result.risk_score == 0.35  # 0.75 raw, capped at 0.35


def test_url_only_evidence_cannot_be_malicious():
    every_url_signal = [
        ev(signal)
        for signal in (
            URL_IP, URL_AT, URL_ANCHOR, URL_PUNYCODE, URL_HTTP, URL_KEYWORDS, URL_LONG,
            URL_DEEP_PATH, DOMAIN_TLD, DOMAIN_SUBDOMAINS, BRAND_LOOKALIKE,
        )
    ] + [brand_in_url(0.85)]
    assert calculate_risk(every_url_signal).verdict == "SUSPICIOUS"


# --- Thresholds ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score, verdict",
    [
        (0.0, "SAFE"),
        (0.29, "SAFE"),
        (0.30, "SUSPICIOUS"),
        (0.69, "SUSPICIOUS"),
        (0.70, "MALICIOUS"),
        (1.0, "MALICIOUS"),
    ],
)
def test_verdict_thresholds(score, verdict):
    assert verdict_for_score(score) == verdict


def test_float_noise_does_not_break_boundaries():
    assert verdict_for_score(0.15 + 0.15) == "SUSPICIOUS"  # 0.3 may be 0.30000000000000004
    assert verdict_for_score(0.1 + 0.2) == "SUSPICIOUS"
    assert verdict_for_score(0.7 - 1e-12) == "MALICIOUS"  # rounds to 0.70


def test_two_authentication_failures_reach_exactly_0_30():
    result = risk(SPF, DKIM)
    assert result.risk_score == 0.30
    assert result.verdict == "SUSPICIOUS"


@pytest.mark.parametrize(
    "contribution, verdict",
    [(0.29, "SAFE"), (0.30, "SUSPICIOUS"), (0.69, "SUSPICIOUS"), (0.70, "MALICIOUS")],
)
def test_thresholds_through_calculate_risk(monkeypatch, contribution, verdict):
    monkeypatch.setitem(risk_engine.REASON_CONTRIBUTIONS, "Test reason", contribution)
    monkeypatch.setitem(risk_engine.FAMILY_CAPS, "CONTENT", 1.0)
    item = Evidence(category="CONTENT", severity=0.5, reason="Test reason", source="test")
    result = calculate_risk([item])
    assert result.risk_score == contribution
    assert result.verdict == verdict


# --- Bounds --------------------------------------------------------------------------------


def _category_for(reason: str) -> str:
    if reason.startswith("Email"):
        return "CONTENT"
    if reason.startswith(("URL", "Link", "Possible")):
        return "URL"
    return "HEADER"


def test_score_cannot_exceed_one():
    everything = [
        Evidence(category=_category_for(reason), severity=1.0, reason=reason, source="test")
        for reason in REASON_CONTRIBUTIONS
    ]
    everything.append(brand_in_url(1.0))
    result = calculate_risk(everything)
    assert result.risk_score == 1.0
    assert result.verdict == "MALICIOUS"
    assert result.confidence == "HIGH"
    assert result.risk_score <= 1.0


def test_score_cannot_be_negative():
    assert clamp_score(-0.5) == 0.0
    assert clamp_score(1.7) == 1.0
    assert verdict_for_score(-1.0) == "SAFE"
    assert calculate_risk([]).risk_score >= 0.0


def test_risk_result_model_rejects_out_of_range_values():
    with pytest.raises(ValidationError):
        RiskResult(risk_score=1.2, verdict="SAFE", confidence="LOW", evidence_count=0)
    with pytest.raises(ValidationError):
        RiskResult(risk_score=0.5, verdict="UNKNOWN", confidence="LOW", evidence_count=0)


def test_score_is_rounded_to_two_decimals():
    result = risk(SPF, RETURN_PATH, MESSAGE_ID)
    assert result.risk_score == round(result.risk_score, 2) == 0.30


# --- Confidence ----------------------------------------------------------------------------


def test_confidence_low_for_no_evidence_or_single_signal():
    assert calculate_risk([]).confidence == "LOW"
    assert risk(CREDENTIALS).confidence == "LOW"
    assert risk(CTA).confidence == "LOW"
    assert risk(GREETING, CTA).confidence == "LOW"  # only one meaningful signal


def test_confidence_increases_with_signal_diversity():
    one_family = risk(CREDENTIALS)
    two_families = risk(SPF, CREDENTIALS)
    three_families = risk(SPF, URL_IP, CREDENTIALS)
    assert (one_family.confidence, two_families.confidence, three_families.confidence) == (
        "LOW",
        "MEDIUM",
        "HIGH",
    )


def test_confidence_medium_for_multiple_meaningful_items_in_one_family():
    assert risk(URGENCY, VERIFICATION).confidence == "MEDIUM"


def test_confidence_high_for_several_strong_indicators_agreeing():
    assert risk(DMARC, SPF, DKIM).confidence == "HIGH"


def test_three_weak_families_are_not_high_confidence():
    assert risk(CTA, URL_KEYWORDS, MESSAGE_ID, DOMAIN_TLD).confidence == "MEDIUM"


# --- Robustness and drift protection -------------------------------------------------------


def test_unknown_reason_or_category_does_not_inflate_or_crash():
    unknown_reason = Evidence(category="CONTENT", severity=1.0, reason="Something new", source="x")
    unknown_category = Evidence(category="OTHER", severity=1.0, reason="Whatever", source="x")
    result = calculate_risk([unknown_reason, unknown_category])
    assert result.risk_score == 0.0
    assert result.evidence_count == 2
    assert result.categories_detected == ["CONTENT", "OTHER"]
    assert result.verdict == "SAFE"


def test_severity_is_not_used_as_the_score():
    low = calculate_risk([Evidence(category="CONTENT", severity=0.0, reason=CREDENTIALS[1], source="t")])
    high = calculate_risk([Evidence(category="CONTENT", severity=1.0, reason=CREDENTIALS[1], source="t")])
    assert low.risk_score == high.risk_score == 0.15


def test_calculate_risk_is_deterministic_and_order_independent():
    items = [ev(SPF), ev(URL_IP), ev(CREDENTIALS), ev(URGENCY)]
    forward = calculate_risk(items)
    backward = calculate_risk(list(reversed(items)))
    assert forward == backward == calculate_risk(items)


def test_every_contribution_reason_exists_in_an_analyzer():
    analyzer_source = "".join(
        (BACKEND_DIR / "app" / "analysis" / name).read_text(encoding="utf-8")
        for name in (
            "header_analyzer.py", "url_analyzer.py", "brand_analyzer.py", "content_analyzer.py"
        )
    )
    for reason in [*REASON_CONTRIBUTIONS, BRAND_IN_URL_REASON]:
        if reason.endswith(" authentication failed"):
            continue  # built from an f-string in header_analyzer; covered by the emitted-reason test
        assert reason in analyzer_source, f"'{reason}' is not emitted by any analyzer"


def test_every_reason_emitted_by_analyzers_has_a_contribution():
    from app.schemas.parsed_email import ParsedEmail
    from app.schemas.url import ExtractedURL

    parsed = ParsedEmail(
        from_="PayPal Security <a@xn--evil.com>",
        reply_to="x@other.net",
        return_path="<b@third.org>",
        message_id="<1@fourth.io>",
        spf="fail",
        dkim="fail",
        dmarc="fail",
    )
    emitted = analyze_headers(parsed)
    emitted += analyze_headers(ParsedEmail(from_="admin@[203.0.113.9]"))
    emitted += analyze_headers(ParsedEmail(from_="Just A Name"))

    urls = [
        ExtractedURL(url="http://192.168.1.10/login"),
        ExtractedURL(url="https://paypal.com@evil.xyz/account/verify/a/b/c/d/e/f?x=" + "a" * 200),
        ExtractedURL(url="https://xn--pypal-4ve.com/"),
        ExtractedURL(url="https://a.b.c.d.example.top/", anchor_text="PayPal Login"),
        ExtractedURL(url="https://paypal-verify.example.net/"),
        ExtractedURL(url="https://paypa1.com/"),
        ExtractedURL(url="https://random.example.org/paypal/login"),
        ExtractedURL(url="https://a-b-c-d-e-f.example.com/"),
    ]
    for item in urls:
        emitted += build_url_analysis(item).evidence

    emitted += analyze_content(
        ParsedEmail(
            subject="Final warning",
            plain_text_body=(
                "Dear customer, PayPal Security: your account will be suspended. Enter your password "
                "and share your OTP. Verify your account, pay the outstanding invoice. Click here."
            ),
        )
    )

    assert emitted
    for item in emitted:
        assert item.reason in REASON_CONTRIBUTIONS or item.reason == BRAND_IN_URL_REASON, item.reason


# --- End-to-end through the real analyzers (no API integration) ------------------------------


def analyze_everything(raw_email: str) -> list[Evidence]:
    parsed = parse_email(raw_email)
    evidence = analyze_headers(parsed) + analyze_content(parsed)
    for extracted in extract_urls(parsed):
        evidence += build_url_analysis(extracted).evidence
    return evidence


def test_end_to_end_phishing_sample_is_malicious():
    raw = json.loads((BACKEND_DIR / "sample_request.json").read_text(encoding="utf-8"))["email_text"]
    result = calculate_risk(analyze_everything(raw))
    assert result.verdict == "MALICIOUS"
    assert result.confidence == "HIGH"
    assert result.signal_families == ["CONTENT", "HEADER", "URL"]
    assert 0.0 <= result.risk_score <= 1.0


def test_end_to_end_ordinary_email_is_safe():
    raw = (
        "From: Sam <sam@example.com>\n"
        "To: team@example.com\n"
        "Subject: Meeting notes\n"
        "Message-ID: <abc@mail.example.com>\n"
        "Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass\n"
        "\n"
        "Hi team, the notes are at https://docs.example.com/notes. Our monthly invoice is attached.\n"
    )
    result = calculate_risk(analyze_everything(raw))
    assert result.verdict == "SAFE"
    assert result.risk_score == 0.0
    assert result.confidence == "LOW"
