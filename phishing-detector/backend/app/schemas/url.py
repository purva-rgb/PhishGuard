from typing import Optional

from pydantic import BaseModel, Field

from app.schemas.evidence import Evidence


class ExtractedURL(BaseModel):
    url: str
    anchor_text: Optional[str] = None


class URLAnalysis(BaseModel):
    url: str
    hostname: Optional[str] = None
    registrable_domain: Optional[str] = None
    scheme: Optional[str] = None
    evidence: list[Evidence] = Field(default_factory=list)
