from fastapi import APIRouter

from app.analysis.content_analyzer import analyze_content
from app.analysis.explanation_engine import generate_explanation
from app.analysis.header_analyzer import analyze_headers
from app.analysis.risk_engine import calculate_risk
from app.analysis.url_analyzer import build_url_analysis
from app.preprocessing.email_parser import parse_email
from app.preprocessing.url_extractor import extract_urls
from app.schemas.email import EmailAnalyzeRequest, EmailAnalyzeResponse
from app.schemas.evidence import Evidence

router = APIRouter(prefix="/api/analyze", tags=["email"])


def run_analysis(email_text: str) -> EmailAnalyzeResponse:
    """Compose the existing Part 2–7 analyzers. Does not change their scoring or explanations."""
    parsed = parse_email(email_text)

    evidence: list[Evidence] = []
    evidence.extend(analyze_headers(parsed))
    for extracted_url in extract_urls(parsed):
        evidence.extend(build_url_analysis(extracted_url).evidence)
    evidence.extend(analyze_content(parsed))

    risk_result = calculate_risk(evidence)
    explanation = generate_explanation(evidence, risk_result)
    return EmailAnalyzeResponse(
        **explanation.model_dump(),
        signal_families=list(risk_result.signal_families),
    )


@router.post("/email", response_model=EmailAnalyzeResponse)
def analyze_email(request: EmailAnalyzeRequest) -> EmailAnalyzeResponse:
    return run_analysis(request.email_text)
