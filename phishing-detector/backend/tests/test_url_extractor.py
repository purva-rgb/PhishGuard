from app.preprocessing.url_extractor import extract_urls
from app.preprocessing.url_utils import normalize_url
from app.preprocessing.email_parser import parse_email
from app.schemas.parsed_email import ParsedEmail


def make_email(plain=None, html=None) -> ParsedEmail:
    return ParsedEmail(plain_text_body=plain, html_body=html)


def urls_of(result):
    return [item.url for item in result]


def test_plain_text_url():
    result = extract_urls(make_email(plain="Please visit https://example.com/login today."))
    assert len(result) == 1
    assert result[0].url == "https://example.com/login"
    assert result[0].anchor_text is None


def test_trailing_punctuation_is_not_part_of_url():
    result = extract_urls(
        make_email(plain="See (https://example.com/a), or https://example.com/b. Also http://x.org/c!")
    )
    assert urls_of(result) == ["https://example.com/a", "https://example.com/b", "http://x.org/c"]


def test_multiple_urls():
    result = extract_urls(
        make_email(plain="One: https://a.example.com/x\nTwo: http://b.example.org/y?z=1\n")
    )
    assert urls_of(result) == ["https://a.example.com/x", "http://b.example.org/y?z=1"]


def test_duplicate_urls_are_removed():
    plain = "https://example.com\nhttps://example.com/\nhttps://example.com\nHTTPS://EXAMPLE.COM/"
    result = extract_urls(make_email(plain=plain))
    assert len(result) == 1
    assert result[0].url == "https://example.com"  # original text is preserved


def test_http_and_https_variants_are_kept_separate():
    result = extract_urls(make_email(plain="http://example.com and https://example.com"))
    assert len(result) == 2


def test_different_paths_are_not_merged():
    result = extract_urls(make_email(plain="https://example.com/a https://example.com/b"))
    assert len(result) == 2


def test_html_href():
    html = '<html><body><a href="https://example.com/login">x</a></body></html>'
    result = extract_urls(make_email(html=html))
    assert urls_of(result) == ["https://example.com/login"]


def test_html_anchor_text_and_href():
    html = (
        '<p>Hello</p><a class="btn" href="https://example.com/login">\n'
        "   Verify <b>your</b>   account\n</a>"
    )
    result = extract_urls(make_email(html=html))
    assert len(result) == 1
    assert result[0].url == "https://example.com/login"
    assert result[0].anchor_text == "Verify your account"


def test_html_entities_in_href_are_decoded():
    html = '<a href="https://example.com/p?a=1&amp;b=2">go</a>'
    result = extract_urls(make_email(html=html))
    assert urls_of(result) == ["https://example.com/p?a=1&b=2"]


def test_non_http_links_are_ignored():
    html = (
        '<a href="mailto:a@example.com">m</a><a href="javascript:void(0)">j</a>'
        '<a href="#top">t</a><a href="/relative/path">r</a><a href="https://ok.example.com">ok</a>'
    )
    assert urls_of(extract_urls(make_email(html=html))) == ["https://ok.example.com"]


def test_script_and_style_content_is_ignored():
    html = "<style>.a{background:url(https://cdn.example.com/x.png)}</style><script>var u='https://js.example.com/'</script>"
    assert extract_urls(make_email(html=html)) == []


def test_mixed_plain_text_and_html_merges_duplicates_and_keeps_anchor():
    plain = "Verify here: https://example.com/verify and also http://other.example.org/page"
    html = '<a href="https://example.com/verify/">Verify now</a>'
    result = extract_urls(make_email(plain=plain, html=html))

    assert len(result) == 2
    by_url = {item.url: item for item in result}
    assert by_url["https://example.com/verify/"].anchor_text == "Verify now"
    assert by_url["http://other.example.org/page"].anchor_text is None


def test_visible_url_text_in_html_is_extracted():
    result = extract_urls(make_email(html="<p>Go to https://example.com/visible now</p>"))
    assert urls_of(result) == ["https://example.com/visible"]


def test_no_urls():
    assert extract_urls(make_email(plain="Hello, no links here.")) == []
    assert extract_urls(make_email()) == []


def test_malformed_html_does_not_crash():
    html = '<a href="https://example.com/x"><b>unclosed <a href="https://example.com/y">second'
    result = extract_urls(make_email(html=html))
    assert urls_of(result) == ["https://example.com/x", "https://example.com/y"]


def test_normalize_url_key():
    assert normalize_url(" https://Example.com/ ") == normalize_url("https://example.com")
    assert normalize_url("https://example.com/a") != normalize_url("https://example.com/b")


def test_end_to_end_from_parsed_email():
    raw = (
        "From: a@example.com\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/alternative; boundary="B"\n'
        "\n"
        "--B\nContent-Type: text/plain; charset=utf-8\n\nVerify: http://evil.example.xyz/login\n"
        "--B\nContent-Type: text/html; charset=utf-8\n\n"
        '<a href="http://evil.example.xyz/login">PayPal Login</a>\n'
        "--B--\n"
    )
    result = extract_urls(parse_email(raw))
    assert len(result) == 1
    assert result[0].anchor_text == "PayPal Login"
