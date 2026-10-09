from typing import Literal

from pydantic import BaseModel, Field


class RiskResult(BaseModel):
    risk_score: float = Field(ge=0.0, le=1.0)
    verdict: Literal["SAFE", "SUSPICIOUS", "MALICIOUS"]
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    evidence_count: int = Field(ge=0)
    categories_detected: list[str] = Field(default_factory=list)
    signal_families: list[str] = Field(default_factory=list)
