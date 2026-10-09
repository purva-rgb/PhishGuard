import pytest
from pydantic import ValidationError

from app.analysis.header_analyzer import analyze_headers
from app.preprocessing.email_parser import parse_email
from app.schemas.evidence import Evidence
from app.schemas.parsed_email import ParsedEmail

REPLY_TO = "Reply-To domain differs from sender domain"
RETURN_PATH = "Return-Path domain differs from sender domain"
SPF = "SPF authentication failed"
DKIM = "DKIM authentication failed"
DMARC = "DMARC authentication failed"
BRAND = "Display name may impersonate a known brand"
MESSAGE_ID = "Message-ID domain differs from sender domain"


def make_email(**fields) -> ParsedEmail:
    return ParsedEmail(**fields)


def reasons(evidence: list[Evidence]) -> list[str]:
    return [item.reason for item in evidence]


def find(evidence: list[Evidence], reason: str) -> Evidence:
    matches = [item for item in evidence if item.reason == reason]
    assert len(matches) == 1, f"expected one '{reason}', got {reasons(evidence)}"
    return matches[0]


def test_matching_from_and_reply_to_has_no_mismatch():
    evidence = analyze_headers(
        make_email(from_="Alice <alice@example.com>", reply_to="support@example.com")
    )
    assert REPLY_TO not in reasons(evidence)
    assert evidence == []


def test_subdomain_is_not_a_mismatch():
    evidence = analyze_headers(
        make_email(
            from_="alice@example.com",
            reply_to="x@mail.example.com",
            return_path="<bounce@bounces.example.com>",
        )
    )
    assert evidence == []


def test_reply_to_domain_mismatch():
    evidence = analyze_headers(
        make_email(
            from_="PayPal Support <security@paypal.com>",
            reply_to="verify@suspicious-example.net",
        )
    )
    item = find(evidence, REPLY_TO)
    assert item.category == "HEADER"
    assert item.severity == 0.8
    assert item.source == "header_analyzer"
    assert item.observed_value == "security@paypal.com -> verify@suspicious-example.net"


def test_return_path_domain_mismatch():
    evidence = analyze_headers(
        make_email(from_="alice@example.com", return_path="<bounce@other-domain.net>")
    )
    item = find(evidence, RETURN_PATH)
    assert item.category == "HEADER"
    assert item.severity == 0.7
    assert item.source == "header_analyzer"
    assert "other-domain.net" in item.observed_value


def test_spf_fail():
    evidence = analyze_headers(make_email(from_="a@example.com", spf="fail"))
    item = find(evidence, SPF)
    assert item.category == "AUTHENTICATION"
    assert item.severity == 0.9
    assert item.source == "header_analyzer"


def test_dkim_fail():
    evidence = analyze_headers(make_email(from_="a@example.com", dkim="fail"))
    item = find(evidence, DKIM)
    assert item.category == "AUTHENTICATION"
    assert item.severity == 0.8


def test_dmarc_fail():
    evidence = analyze_headers(make_email(from_="a@example.com", dmarc="fail"))
    item = find(evidence, DMARC)
    assert item.category == "AUTHENTICATION"
    assert item.severity == 0.95


def test_all_authentication_pass_has_no_evidence():
    evidence = analyze_headers(
        make_email(from_="a@example.com", spf="pass", dkim="pass", dmarc="pass")
    )
    assert evidence == []


def test_missing_authentication_has_no_evidence():
    evidence = analyze_headers(make_email(from_="a@example.com"))
    assert evidence == []


@pytest.mark.parametrize("value", ["unknown", "none", "neutral", "softfail"])
def test_non_fail_authentication_values_are_not_flagged(value):
    evidence = analyze_headers(
        make_email(from_="a@example.com", spf=value, dkim=value, dmarc=value)
    )
    assert evidence == []


def test_brand_display_name_with_unrelated_domain():
    evidence = analyze_headers(
        make_email(from_="PayPal Security <security@random-domain.xyz>")
    )
    item = find(evidence, BRAND)
    assert item.category == "HEADER"
    assert item.severity == 0.75
    assert "PayPal Security" in item.observed_value
    assert "random-domain.xyz" in item.observed_value


def test_microsoft_display_name_with_unrelated_domain():
    evidence = analyze_headers(
        make_email(from_="Microsoft Account Team <account@random-domain.xyz>")
    )
    assert BRAND in reasons(evidence)


def test_brand_display_name_with_legitimate_domain_is_not_flagged():
    for sender in (
        "PayPal Support <service@paypal.com>",
        "PayPal Support <service@mail.paypal.com>",
        "Amazon <order-update@amazon.co.uk>",
        "Google <no-reply@accounts.google.com>",
    ):
        assert BRAND not in reasons(analyze_headers(make_email(from_=sender))), sender


def test_brand_must_be_a_whole_word():
    evidence = analyze_headers(make_email(from_="Metaphor Studio <hi@metaphor.example>"))
    assert BRAND not in reasons(evidence)


def test_custom_brand_list():
    brands = {"acme": frozenset({"acme.com"})}
    evidence = analyze_headers(
        make_email(from_="ACME Billing <billing@evil.example>"), brand_domains=brands
    )
    assert BRAND in reasons(evidence)


def test_message_id_domain_mismatch():
    evidence = analyze_headers(
        make_email(from_="a@example.com", message_id="<123.abc@mailer.other-host.net>")
    )
    item = find(evidence, MESSAGE_ID)
    assert item.category == "HEADER"
    assert item.severity == 0.4
    assert item.source == "header_analyzer"


def test_matching_message_id_is_not_flagged():
    evidence = analyze_headers(
        make_email(from_="a@example.com", message_id="<123.abc@mail.example.com>")
    )
    assert evidence == []


def test_punycode_sender_domain():
    evidence = analyze_headers(make_email(from_="Shop <info@xn--pypal-4ve.com>"))
    item = find(evidence, "Sender domain uses punycode (xn--)")
    assert item.category == "HEADER"
    assert item.observed_value == "xn--pypal-4ve.com"


def test_ip_based_sender_domain():
    evidence = analyze_headers(make_email(from_="admin <admin@[203.0.113.9]>"))
    item = find(evidence, "Sender domain is an IP address")
    assert item.observed_value == "203.0.113.9"

    evidence = analyze_headers(make_email(from_="admin@203.0.113.9"))
    assert "Sender domain is an IP address" in reasons(evidence)


def test_invalid_sender_domain_is_flagged_but_absent_from_is_not():
    assert "Sender domain is missing or invalid" in reasons(
        analyze_headers(make_email(from_="Just A Name"))
    )
    assert analyze_headers(make_email()) == []


def test_missing_optional_headers_are_not_evidence():
    evidence = analyze_headers(
        make_email(from_="a@example.com", reply_to=None, return_path=None, message_id=None)
    )
    assert evidence == []


def test_empty_email_does_not_crash():
    assert analyze_headers(parse_email("x")) == []
    assert analyze_headers(parse_email("")) == []


def test_severity_must_be_between_0_and_1():
    with pytest.raises(ValidationError):
        Evidence(category="HEADER", severity=1.5, reason="x", source="y")
    with pytest.raises(ValidationError):
        Evidence(category="HEADER", severity=-0.1, reason="x", source="y")


def test_end_to_end_with_parser():
    raw = (
        "Return-Path: <bounce@mailer.suspicious-example.net>\n"
        "Authentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail\n"
        'From: "PayPal Support" <service@paypal.com>\n'
        "Reply-To: help-desk@suspicious-example.net\n"
        "Message-ID: <1@mailer.suspicious-example.net>\n"
        "Subject: Verify\n"
        "\n"
        "body\n"
    )
    evidence = analyze_headers(parse_email(raw))
    assert set(reasons(evidence)) == {REPLY_TO, RETURN_PATH, SPF, DMARC, MESSAGE_ID}
