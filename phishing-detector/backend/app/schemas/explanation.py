from typing import Literal, Optional

from pydantic import BaseModel, Field


class ExplanationReason(BaseModel):
    reason: str
    severity: float = Field(ge=0.0, le=1.0)
    category: str
    observed_value: Optional[str] = None


class ExplanationResult(BaseModel):
    verdict: Literal["SAFE", "SUSPICIOUS", "MALICIOUS"]
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    summary: str
    reasons: list[ExplanationReason] = Field(default_factory=list)
    recommended_action: str
    evidence_count: int = Field(ge=0)
    categories_detected: list[str] = Field(default_factory=list)
