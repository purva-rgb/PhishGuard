import pytest

from app.analysis.content_analyzer import analyze_content
from app.preprocessing.email_parser import parse_email
from app.schemas.evidence import Evidence
from app.schemas.parsed_email import ParsedEmail

URGENCY = "Email uses strong urgency or threat language"
CREDENTIALS = "Email requests sensitive account credentials"
OTP = "Email requests a security or verification code"
VERIFICATION = "Email requests account or identity verification"
PAYMENT = "Email requests payment or sensitive financial information"
CTA = "Email contains a suspicious call to action"
BRAND = "Email uses language associated with a known brand or service"
GREETING = "Email uses a generic recipient greeting"


def analyze(body=None, subject=None, html=None) -> list[Evidence]:
    return analyze_content(ParsedEmail(plain_text_body=body, subject=subject, html_body=html))


def reasons(evidence: list[Evidence]) -> list[str]:
    return [item.reason for item in evidence]


def find(evidence: list[Evidence], reason: str) -> Evidence:
    matches = [item for item in evidence if item.reason == reason]
    assert len(matches) == 1, f"expected one '{reason}', got {reasons(evidence)}"
    return matches[0]


def test_normal_informational_email_has_no_evidence():
    body = (
        "Hi team,\n\nAttached are the notes from yesterday's planning meeting. "
        "Let me know if you have questions. The next sync is on Friday.\n\nThanks,\nSam"
    )
    assert analyze(body, subject="Meeting notes") == []


def test_urgent_account_suspension():
    evidence = analyze("Your account will be suspended within 24 hours.", subject="Notice")
    item = find(evidence, URGENCY)
    assert item.category == "CONTENT"
    assert item.severity == 0.5
    assert item.source == "content_analyzer"
    assert "account will be suspended" in item.observed_value.lower()


def test_multiple_weak_urgency_indicators_are_enough():
    assert URGENCY in reasons(analyze("This is urgent. Action required before the deadline."))


def test_single_urgency_word_is_not_enough():
    assert analyze("Urgent: The office meeting has moved to 3 PM.") == []
    assert URGENCY not in reasons(analyze("Please send the report immediately after the call."))
    assert URGENCY not in reasons(analyze("Action required: submit your timesheet by Friday."))


def test_credential_request():
    for text in (
        "Please enter your password to continue.",
        "Provide your username and password below.",
        "Confirm your login credentials.",
        "We need you to verify your password.",
        "Sign in to verify your details.",
        "Please confirm your login.",
    ):
        item = find(analyze(text), CREDENTIALS)
        assert item.category == "CONTENT"
        assert item.severity == 0.8
        assert item.observed_value


def test_otp_request():
    for text in (
        "Reply with your OTP to confirm.",
        "Please share the verification code you received.",
        "Send us your one-time password.",
        "Enter your security code on the page.",
        "Provide the MFA code to our agent.",
    ):
        item = find(analyze(text), OTP)
        assert item.category == "CONTENT"
        assert item.severity == 0.8


def test_account_verification_request():
    for text in (
        "Please verify your account.",
        "Confirm your identity to continue.",
        "Account verification required.",
        "Your account requires verification.",
        "Complete the security verification.",
    ):
        item = find(analyze(text), VERIFICATION)
        assert item.severity == 0.5


def test_payment_request():
    for text in (
        "Please provide your bank details.",
        "Send your card number to complete the order.",
        "Please pay the outstanding invoice today.",
        "Make a wire transfer to the account below.",
        "Transfer the funds to our wallet.",
        "Please pay in bitcoin.",
    ):
        item = find(analyze(text), PAYMENT)
        assert item.severity == 0.7, text


def test_suspicious_call_to_action():
    item = find(analyze("Secure your account: login now."), CTA)
    assert item.category == "CONTENT"
    assert item.severity == 0.35
    assert CTA in reasons(analyze("Please verify now."))


def test_plain_click_here_alone_is_not_flagged():
    assert analyze("To read our newsletter archive, click here.") == []


def test_click_here_is_flagged_when_combined_with_other_signals():
    evidence = analyze("Please verify your account. Click here to continue.")
    assert CTA in reasons(evidence)
    assert VERIFICATION in reasons(evidence)


def test_combined_signals_produce_multiple_independent_evidence():
    body = (
        "Dear customer, your account will be suspended unless you verify your password "
        "immediately. Click here to confirm your account."
    )
    evidence = analyze(body, subject="Action required")
    found = set(reasons(evidence))
    assert {URGENCY, CREDENTIALS, VERIFICATION, CTA, GREETING} <= found


def test_invoice_with_immediate_payment_gives_payment_and_urgency():
    found = reasons(analyze("Please review the invoice and pay immediately."))
    assert PAYMENT in found
    assert URGENCY in found


def test_generic_greeting_is_low_severity_only():
    evidence = analyze("Dear valued customer,\n\nThank you for shopping with us.")
    assert reasons(evidence) == [GREETING]
    assert evidence[0].severity == 0.15
    assert evidence[0].category == "CONTENT"
    for greeting in ("Dear user,", "Dear account holder,", "Dear Customer"):
        assert reasons(analyze(greeting)) == [GREETING]


def test_brand_language_requires_suspicious_context():
    assert analyze("PayPal Security sent you a monthly summary of your activity.") == []
    assert analyze("Microsoft Account Team: welcome to your new device.") == []

    evidence = analyze("PayPal Security: please verify your account.")
    item = find(evidence, BRAND)
    assert item.severity == 0.4
    assert "PayPal Security" in item.observed_value
    assert VERIFICATION in reasons(evidence)

    assert BRAND in reasons(analyze("Microsoft Account Team: enter your password now."))
    assert BRAND in reasons(analyze("Google Support needs you to verify your account."))


# --- false-positive guards ---------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "The password policy was updated.",
        "Your password was changed successfully.",
        "Please read our account security documentation.",
        "We will never ask you to enter your password by email.",
        "Never share your password with anyone.",
    ],
)
def test_informational_password_mentions_are_not_credential_requests(text):
    assert CREDENTIALS not in reasons(analyze(text))


@pytest.mark.parametrize(
    "text",
    [
        "Your OTP was successfully generated.",
        "Your verification code is 482913.",
        "Do not share your OTP with anyone.",
        "Never give your security code to anyone, including our staff.",
    ],
)
def test_informational_otp_mentions_are_not_otp_requests(text):
    assert OTP not in reasons(analyze(text))


@pytest.mark.parametrize(
    "text",
    [
        "Our monthly invoice is attached.",
        "Your payment was received. Thank you!",
        "The invoice for March is available in your dashboard.",
        "We have sent the payment confirmation to your email.",
        "We will never ask you to provide your card number.",
    ],
)
def test_informational_payment_mentions_are_not_payment_requests(text):
    assert PAYMENT not in reasons(analyze(text))


def test_account_security_documentation_is_clean():
    assert analyze("Please read our account security documentation.") == []


# --- HTML, empty and repeated input ------------------------------------------------------


def test_html_only_email_is_analyzed():
    html = (
        "<html><head><title>Notice</title><style>p{color:red}</style></head><body>"
        "<p>Your account will be suspended.</p>"
        "<p>Please <b>verify</b> your <i>account</i> and enter your password.</p>"
        "<script>var x = 'verify your account';</script></body></html>"
    )
    found = reasons(analyze(html=html))
    assert URGENCY in found
    assert CREDENTIALS in found
    assert VERIFICATION in found


def test_plain_text_is_preferred_over_html():
    evidence = analyze(
        body="Lunch is at noon.",
        html="<p>Your account will be suspended. Verify your account.</p>",
    )
    assert evidence == []


def test_blank_plain_text_falls_back_to_html():
    evidence = analyze(body="   ", html="<p>Please enter your password.</p>")
    assert CREDENTIALS in reasons(evidence)


def test_empty_body_returns_empty_list():
    assert analyze_content(ParsedEmail()) == []
    assert analyze("") == []
    assert analyze("   \n  ", subject="  ") == []
    assert analyze(html="") == []
    assert analyze(html="<html><body></body></html>") == []


def test_malformed_html_does_not_crash():
    assert isinstance(analyze(html="<div><p>unclosed <b>tags <a href="), list)


def test_repeated_phrase_is_deduplicated():
    body = "Verify your account. " * 10
    evidence = analyze(body)
    assert reasons(evidence).count(VERIFICATION) == 1
    item = find(evidence, VERIFICATION)
    assert item.observed_value.lower().count("verify your account") == 1


def test_repeated_mixed_signals_produce_one_evidence_per_reason():
    body = "Enter your password. Verify your account immediately. " * 8
    evidence = analyze(body)
    assert len(reasons(evidence)) == len(set(reasons(evidence)))


def test_case_and_whitespace_are_normalized():
    evidence = analyze("PLEASE   ENTER\n\n  YOUR    PASSWORD   now")
    assert CREDENTIALS in reasons(evidence)


def test_subject_is_included():
    evidence = analyze("See details inside.", subject="Final warning: verify your account")
    found = reasons(evidence)
    assert URGENCY in found
    assert VERIFICATION in found


def test_all_severities_are_valid():
    body = (
        "Dear customer, PayPal Security: your account will be suspended immediately. "
        "Verify your password and enter your OTP, then pay the outstanding invoice. Click here."
    )
    evidence = analyze(body, subject="Final warning")
    assert evidence
    for item in evidence:
        assert 0 <= item.severity <= 1
        assert item.source == "content_analyzer"
        assert item.category == "CONTENT"


def test_end_to_end_with_parser():
    raw = (
        "From: PayPal Security <service@paypal.com>\n"
        "Subject: Action required: verify your account\n"
        "\n"
        "Dear customer, your account will be suspended unless you enter your password.\n"
    )
    found = reasons(analyze_content(parse_email(raw)))
    assert {URGENCY, CREDENTIALS, VERIFICATION, GREETING} <= set(found)
