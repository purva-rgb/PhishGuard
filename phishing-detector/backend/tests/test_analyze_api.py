from fastapi.testclient import TestClient

from app.analysis.explanation_engine import generate_explanation
from app.analysis.risk_engine import calculate_risk
from app.api.email import run_analysis
from app.main import app
from app.preprocessing.email_parser import parse_email
from app.schemas.email import EmailAnalyzeResponse

client = TestClient(app)

DEMO = (
    "From: security@paypa1-login.xyz\n"
    "Reply-To: verify@randommail.xyz\n"
    "Subject: URGENT: Your PayPal account will be suspended\n"
    "\n"
    "Your account requires immediate verification.\n"
    "Please verify your account by clicking the link below:\n"
    "https://paypa1-login.xyz/verify\n"
    "Failure to verify your account within 24 hours may result in suspension.\n"
    "This is a fake demonstration email.\n"
    "Do not send it anywhere.\n"
)

NORMAL = (
    "From: newsletter@your-company.com\n"
    "Subject: Weekly Newsletter\n"
    "\n"
    "Here are this week's updates.\n"
    "Thanks for reading.\n"
)


def test_blank_email_still_returns_422():
    assert client.post("/api/analyze/email", json={"email_text": "  "}).status_code == 422
    assert client.post("/api/analyze/email", json={"email_text": ""}).status_code == 422
    assert client.post("/api/analyze/email", json={}).status_code == 422


def test_response_shape_matches_explanation_plus_signal_families():
    response = client.post("/api/analyze/email", json={"email_text": DEMO})
    assert response.status_code == 200
    data = response.json()
    EmailAnalyzeResponse.model_validate(data)

    for key in (
        "verdict", "risk_score", "confidence", "summary", "reasons",
        "recommended_action", "evidence_count", "categories_detected", "signal_families",
    ):
        assert key in data
    assert "status" not in data
    assert "email" not in data
    assert data["verdict"] in {"SAFE", "SUSPICIOUS", "MALICIOUS"}
    assert data["confidence"] in {"LOW", "MEDIUM", "HIGH"}
    assert 0.0 <= data["risk_score"] <= 1.0
    assert isinstance(data["reasons"], list)
    assert len(data["reasons"]) <= 5
    if data["reasons"]:
        assert "reason" in data["reasons"][0]
        assert "severity" in data["reasons"][0]


def test_demo_email_is_high_risk():
    data = client.post("/api/analyze/email", json={"email_text": DEMO}).json()
    assert data["verdict"] == "MALICIOUS"
    assert data["risk_score"] >= 0.70
    assert data["confidence"] == "HIGH"
    assert len(data["reasons"]) >= 2
    assert data["evidence_count"] >= len(data["reasons"])
    assert set(data["signal_families"]) >= {"HEADER", "URL", "CONTENT"}


def test_normal_email_is_low_risk():
    data = client.post("/api/analyze/email", json={"email_text": NORMAL}).json()
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] < 0.30


def test_endpoint_matches_pipeline_and_does_not_rescore():
    response = run_analysis(DEMO)
    from app.analysis.content_analyzer import analyze_content
    from app.analysis.header_analyzer import analyze_headers
    from app.analysis.url_analyzer import build_url_analysis
    from app.preprocessing.url_extractor import extract_urls

    parsed = parse_email(DEMO)
    evidence = analyze_headers(parsed)
    for extracted in extract_urls(parsed):
        evidence += build_url_analysis(extracted).evidence
    evidence += analyze_content(parsed)
    risk = calculate_risk(evidence)
    explanation = generate_explanation(evidence, risk)

    assert response.verdict == explanation.verdict == risk.verdict
    assert response.risk_score == explanation.risk_score == risk.risk_score
    assert response.confidence == explanation.confidence == risk.confidence
    assert response.summary == explanation.summary
    assert response.recommended_action == explanation.recommended_action
    assert response.reasons == explanation.reasons
    assert response.signal_families == risk.signal_families


def test_cors_allows_vite_origins():
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
        response = client.get("/health", headers={"Origin": origin})
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == origin
