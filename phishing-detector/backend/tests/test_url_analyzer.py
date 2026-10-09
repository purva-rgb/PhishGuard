import pytest

from app.analysis.brand_analyzer import analyze_url_brand
from app.analysis.url_analyzer import analyze_url, build_url_analysis
from app.schemas.evidence import Evidence
from app.schemas.url import ExtractedURL

LONG = "URL is unusually long"
IP = "URL uses an IP address instead of a domain"
AT = "URL contains an @ symbol that may obscure the destination"
PUNY = "URL uses a punycode domain"
HTTP = "URL does not use HTTPS"
SUBDOMAINS = "URL contains an unusually deep subdomain structure"
TLD = "URL uses a potentially suspicious top-level domain"
KEYWORDS = "URL contains security-sensitive keywords"
DEEP = "URL has an unusually deep path"
STRUCTURE = "URL has an unusual structure"
MISMATCH = "Link text does not match the actual destination"
BRAND = "Possible brand impersonation in URL"
LOOKALIKE = "Possible brand lookalike domain in URL"


def url(value: str, anchor: str | None = None) -> ExtractedURL:
    return ExtractedURL(url=value, anchor_text=anchor)


def reasons(evidence: list[Evidence]) -> list[str]:
    return [item.reason for item in evidence]


def find(evidence: list[Evidence], reason: str) -> Evidence:
    matches = [item for item in evidence if item.reason == reason]
    assert len(matches) == 1, f"expected one '{reason}', got {reasons(evidence)}"
    return matches[0]


def full_reasons(value: str, anchor: str | None = None) -> list[str]:
    return reasons(build_url_analysis(url(value, anchor)).evidence)


def test_normal_https_url_has_no_evidence():
    assert analyze_url(url("https://example.com/")) == []
    assert analyze_url(url("https://www.example.com/products/shoes?id=42")) == []
    assert full_reasons("https://example.com/about") == []


def test_ip_based_url():
    item = find(analyze_url(url("http://192.168.1.10/login")), IP)
    assert item.category == "URL"
    assert item.severity == 0.8
    assert item.observed_value == "192.168.1.10"
    assert item.source == "url_analyzer"


def test_at_symbol_in_authority():
    evidence = analyze_url(url("https://paypal.com@evil.example/login"))
    item = find(evidence, AT)
    assert item.category == "URL"
    assert item.severity == 0.9
    assert "evil.example" in item.observed_value


def test_at_symbol_in_path_is_not_userinfo():
    assert AT not in reasons(analyze_url(url("https://example.com/user/@handle")))


def test_punycode():
    item = find(analyze_url(url("https://xn--pypal-4ve.com/login")), PUNY)
    assert item.category == "URL"
    assert item.severity == 0.7


def test_http_url():
    evidence = analyze_url(url("http://example.com/page"))
    item = find(evidence, HTTP)
    assert item.severity == 0.3
    assert reasons(evidence) == [HTTP]  # HTTP alone produces only this low-severity evidence


def test_suspicious_tld():
    item = find(analyze_url(url("https://something.xyz/")), TLD)
    assert item.category == "DOMAIN"
    assert item.severity == 0.4
    for tld in ("top", "click", "shop", "work", "zip", "tk", "ml", "ga", "cf"):
        assert TLD in reasons(analyze_url(url(f"https://something.{tld}/")))
    assert TLD not in reasons(analyze_url(url("https://something.com/")))


def test_excessive_subdomains():
    item = find(analyze_url(url("https://login.verify.account.security.example.com/")), SUBDOMAINS)
    assert item.category == "DOMAIN"
    assert item.severity == 0.5


def test_normal_subdomains_are_not_flagged():
    for value in (
        "https://accounts.google.com/",
        "https://mail.eu.example.co.uk/",
        "https://a.b.example.com/",
    ):
        assert SUBDOMAINS not in reasons(analyze_url(url(value))), value


def test_suspicious_keywords_need_more_than_one():
    evidence = analyze_url(url("https://example.com/account/verify"))
    item = find(evidence, KEYWORDS)
    assert item.category == "URL"
    assert item.severity == 0.4
    assert item.observed_value == "account, verify"

    assert KEYWORDS not in reasons(analyze_url(url("https://example.com/login")))
    assert KEYWORDS not in reasons(analyze_url(url("https://example.com/verify")))


def test_deep_path():
    item = find(analyze_url(url("https://example.com/a/b/c/d/e/f/login")), DEEP)
    assert item.severity == 0.3
    assert DEEP not in reasons(analyze_url(url("https://example.com/a/b/c")))


def test_long_url():
    long_url = "https://example.com/path?" + "q=" + "a" * 200
    item = find(analyze_url(url(long_url)), LONG)
    assert item.severity == 0.5
    assert LONG not in reasons(analyze_url(url("https://example.com/path?q=1")))


def test_unusual_structure_requires_clearly_unusual_values():
    assert STRUCTURE not in reasons(analyze_url(url("https://my-shop-2024.example.com/a-b-c")))
    assert STRUCTURE in reasons(analyze_url(url("https://a-b-c-d-e.example.com/")))
    assert STRUCTURE in reasons(analyze_url(url("https://x12345678.example.com/")))


def test_brand_in_legitimate_domains_is_not_flagged():
    for value in (
        "https://paypal.com/login",
        "https://www.paypal.com/signin",
        "https://accounts.google.com/",
        "https://amazon.co.uk/orders",
        "https://www.microsoft.com/",
        "https://login.microsoftonline.com/",
        "https://s3.amazonaws.com/bucket/file",
    ):
        assert analyze_url_brand(url(value)) == [], value
        assert BRAND not in full_reasons(value), value


def test_brand_in_suspicious_domain():
    evidence = analyze_url_brand(url("https://paypal-verify.suspicious-example.net/login"))
    item = find(evidence, BRAND)
    assert item.category == "BRAND"
    assert item.severity == 0.85
    assert item.source == "brand_analyzer"
    assert "paypal" in item.observed_value
    assert "suspicious-example.net" in item.observed_value


def test_brand_with_suspicious_tld():
    item = find(analyze_url_brand(url("https://secure-paypal.xyz/login")), BRAND)
    assert item.severity == 0.85
    assert "secure-paypal.xyz" in item.observed_value


def test_brand_as_subdomain_of_other_domain():
    assert BRAND in reasons(analyze_url_brand(url("https://paypal.com.evil-example.net/login")))


def test_brand_only_in_path_is_lower_severity():
    item = find(analyze_url_brand(url("https://random-site.example.org/paypal/login")), BRAND)
    assert item.severity == 0.5


@pytest.mark.parametrize(
    "value, brand",
    [
        ("https://paypa1.com/login", "paypal"),
        ("https://paypai.com/", "paypal"),
        ("https://micros0ft.com/", "microsoft"),
        ("https://g00gle.com/", "google"),
        ("https://goggle.com/", "google"),
        ("https://rnicrosoft-support.com/", "microsoft"),
        ("https://secure.paypa1-login.net/", "paypal"),
    ],
)
def test_obvious_typo_lookalikes(value, brand):
    item = find(analyze_url_brand(url(value)), LOOKALIKE)
    assert item.category == "BRAND"
    assert item.severity >= 0.85
    assert brand in item.observed_value


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/",
        "https://pineapple.com/",
        "https://metadata.example.org/",
        "https://paypalm-beach-resort.example.com/",
        "https://googol-math.example.com/",
        "https://amazing-deals.example.com/",
        "https://netflick.example.com/",
    ],
)
def test_unrelated_domains_are_not_lookalikes(value):
    assert LOOKALIKE not in reasons(analyze_url_brand(url(value)))


def test_anchor_text_mismatch_with_brand_name():
    evidence = analyze_url(url("https://evil-example.xyz/login", "PayPal Login"))
    item = find(evidence, MISMATCH)
    assert item.category == "URL"
    assert item.severity == 0.85
    assert item.observed_value == "PayPal Login -> evil-example.xyz"


def test_anchor_text_mismatch_with_displayed_url():
    evidence = analyze_url(url("https://evil-example.xyz/login", "https://www.paypal.com/signin"))
    assert MISMATCH in reasons(evidence)


def test_anchor_text_matching_destination_is_not_flagged():
    assert MISMATCH not in reasons(analyze_url(url("https://www.paypal.com/login", "PayPal Login")))
    assert MISMATCH not in reasons(analyze_url(url("https://www.paypal.com/login", "www.paypal.com")))
    assert MISMATCH not in reasons(analyze_url(url("https://example.com/login", "Verify your account")))
    assert MISMATCH not in reasons(analyze_url(url("https://example.com/login", "Click here")))


def test_missing_anchor_text_creates_no_mismatch_evidence():
    assert MISMATCH not in reasons(analyze_url(url("https://evil-example.xyz/login")))
    assert MISMATCH not in reasons(analyze_url(url("https://evil-example.xyz/login", "   ")))


def test_build_url_analysis_structure():
    result = build_url_analysis(
        url("http://login.paypal-verify.suspicious-example.xyz/account/verify", "PayPal Login")
    )
    assert result.url == "http://login.paypal-verify.suspicious-example.xyz/account/verify"
    assert result.hostname == "login.paypal-verify.suspicious-example.xyz"
    assert result.registrable_domain == "suspicious-example.xyz"
    assert result.scheme == "http"
    found = reasons(result.evidence)
    for expected in (HTTP, TLD, KEYWORDS, MISMATCH, BRAND):
        assert expected in found


def test_build_url_analysis_for_ip_and_unparseable_urls():
    result = build_url_analysis(url("http://192.168.1.10/login"))
    assert result.hostname == "192.168.1.10"
    assert result.registrable_domain is None
    assert IP in reasons(result.evidence)

    for bad in ("http://[::1", "https://", "http:///x", "not a url", ""):
        analysis = build_url_analysis(url(bad))  # must not raise
        assert analysis.url == bad


def test_severity_values_are_valid():
    for value in (
        "http://192.168.1.10/a/b/c/d/e/f/login",
        "https://paypal.com@xn--evil.xyz/account/verify",
    ):
        for item in build_url_analysis(url(value)).evidence:
            assert 0 <= item.severity <= 1
