from fastapi.testclient import TestClient

from app.main import app
from app.preprocessing.email_parser import parse_email

client = TestClient(app)


def test_simple_plain_text_email():
    raw = (
        "From: alice@example.com\n"
        "To: bob@example.com\n"
        "Subject: Hello\n"
        "\n"
        "Just a simple message.\n"
    )
    parsed = parse_email(raw)

    assert parsed.from_ == "alice@example.com"
    assert parsed.to == ["bob@example.com"]
    assert parsed.subject == "Hello"
    assert parsed.plain_text_body.strip() == "Just a simple message."
    assert parsed.html_body is None


def test_full_headers():
    raw = (
        "From: Alice Sender <alice@example.com>\n"
        "To: Bob <bob@example.com>, carol@example.com\n"
        "Cc: dave@example.com\n"
        "Reply-To: replies@other.example.net\n"
        "Return-Path: <bounce@example.com>\n"
        "Subject: Quarterly report\n"
        "Date: Wed, 07 Oct 2026 10:15:00 +0000\n"
        "Message-ID: <abc123@example.com>\n"
        "Received: from mail.example.com by mx.example.org;\n"
        "  Wed, 07 Oct 2026 10:15:01 +0000\n"
        "Received: from client by mail.example.com; Wed, 07 Oct 2026 10:14:59 +0000\n"
        "\n"
        "Body text\n"
    )
    parsed = parse_email(raw)

    assert parsed.from_ == "Alice Sender <alice@example.com>"
    assert parsed.to == ["Bob <bob@example.com>", "carol@example.com"]
    assert parsed.cc == ["dave@example.com"]
    assert parsed.reply_to == "replies@other.example.net"
    assert parsed.return_path == "<bounce@example.com>"
    assert parsed.subject == "Quarterly report"
    assert parsed.date == "Wed, 07 Oct 2026 10:15:00 +0000"
    assert parsed.message_id == "<abc123@example.com>"
    assert len(parsed.received) == 2
    assert parsed.received[0].startswith("from mail.example.com by mx.example.org;")


def test_authentication_results_all_pass():
    raw = (
        "From: a@example.com\n"
        "Authentication-Results: mx.example.org;\n"
        "  spf=pass smtp.mailfrom=example.com;\n"
        "  dkim=pass header.d=example.com;\n"
        "  dmarc=pass header.from=example.com\n"
        "Subject: Auth\n"
        "\n"
        "body\n"
    )
    parsed = parse_email(raw)

    assert parsed.spf == "pass"
    assert parsed.dkim == "pass"
    assert parsed.dmarc == "pass"
    assert "spf=pass" in parsed.authentication_results


def test_authentication_results_all_fail():
    raw = (
        "From: a@example.com\n"
        "Authentication-Results: mx.example.org; spf=fail; dkim=fail; dmarc=fail\n"
        "\n"
        "body\n"
    )
    parsed = parse_email(raw)

    assert parsed.spf == "fail"
    assert parsed.dkim == "fail"
    assert parsed.dmarc == "fail"


def test_authentication_results_other_values_and_unrecognized():
    raw = (
        "Authentication-Results: mx.example.org; spf=softfail; dkim=neutral; dmarc=bestguesspass\n"
        "\n"
        "body\n"
    )
    parsed = parse_email(raw)

    assert parsed.spf == "softfail"
    assert parsed.dkim == "neutral"
    assert parsed.dmarc == "unknown"


def test_multipart_plain_and_html():
    raw = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: Multipart\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/alternative; boundary="BOUNDARY"\n'
        "\n"
        "--BOUNDARY\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "\n"
        "Plain version\n"
        "--BOUNDARY\n"
        'Content-Type: text/html; charset="utf-8"\n'
        "\n"
        '<html><body><p>HTML version <a href="http://example.com">link</a></p></body></html>\n'
        "--BOUNDARY--\n"
    )
    parsed = parse_email(raw)

    assert parsed.plain_text_body.strip() == "Plain version"
    assert "<p>HTML version" in parsed.html_body
    assert 'href="http://example.com"' in parsed.html_body


def test_transfer_encodings_and_unknown_charset():
    raw = (
        "From: a@example.com\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/alternative; boundary="B"\n'
        "\n"
        "--B\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Content-Transfer-Encoding: base64\n"
        "\n"
        "SGVsbG8gd29ybGQ=\n"
        "--B\n"
        "Content-Type: text/html; charset=not-a-real-charset\n"
        "Content-Transfer-Encoding: quoted-printable\n"
        "\n"
        "<p>Caf=C3=A9</p>\n"
        "--B--\n"
    )
    parsed = parse_email(raw)

    assert parsed.plain_text_body.strip() == "Hello world"
    assert "<p>Caf" in parsed.html_body


def test_non_multipart_html_email():
    raw = (
        "From: a@example.com\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<b>Hi</b>\n"
    )
    parsed = parse_email(raw)

    assert parsed.html_body.strip() == "<b>Hi</b>"
    assert parsed.plain_text_body is None


def test_missing_authentication_headers():
    raw = "From: a@example.com\nSubject: No auth\n\nbody\n"
    parsed = parse_email(raw)

    assert parsed.authentication_results is None
    assert parsed.spf == "unknown"
    assert parsed.dkim == "unknown"
    assert parsed.dmarc == "unknown"


def test_missing_headers_become_none():
    parsed = parse_email("Subject: Only a subject\n\nbody\n")

    assert parsed.from_ is None
    assert parsed.reply_to is None
    assert parsed.return_path is None
    assert parsed.date is None
    assert parsed.message_id is None
    assert parsed.to == []
    assert parsed.cc == []
    assert parsed.received == []


def test_malformed_input_does_not_crash():
    samples = [
        "x",
        "just some text with no headers at all",
        "From\nTo\n\n\n",
        "From: <<<>>> @@@\nTo: ,,,;;;\nDate: not a date\n\nbody",
        "Content-Type: multipart/mixed\n\nno boundary here",
        "Content-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: \n\n--X--",
        "\x00\x01\x02 binary \udcff junk",
    ]
    for raw in samples:
        parsed = parse_email(raw)
        assert parsed.spf == "unknown"
        assert parsed.dkim == "unknown"
        assert parsed.dmarc == "unknown"


def test_endpoint_still_accepts_a_full_email():
    raw = (
        "From: Support <support@paypa1-secure.example>\n"
        "To: victim@example.com\n"
        "Reply-To: attacker@other.example\n"
        "Return-Path: <bounce@other.example>\n"
        "Subject: Verify your account\n"
        "Authentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail\n"
        "\n"
        "Please verify your account.\n"
    )
    parsed = parse_email(raw)
    assert parsed.from_ == "Support <support@paypa1-secure.example>"
    assert parsed.reply_to == "attacker@other.example"
    assert parsed.return_path == "<bounce@other.example>"
    assert parsed.subject == "Verify your account"
    assert parsed.spf == "fail"
    assert parsed.dkim == "none"
    assert parsed.dmarc == "fail"
    assert "Please verify" in parsed.plain_text_body

    response = client.post("/api/analyze/email", json={"email_text": raw})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in {"SAFE", "SUSPICIOUS", "MALICIOUS"}
    assert 0.0 <= data["risk_score"] <= 1.0
    assert "summary" in data
    assert "recommended_action" in data
    assert isinstance(data["reasons"], list)


def test_endpoint_still_rejects_blank_input():
    assert client.post("/api/analyze/email", json={"email_text": "  "}).status_code == 422
