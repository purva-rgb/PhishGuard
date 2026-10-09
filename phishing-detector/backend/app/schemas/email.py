from pydantic import BaseModel, Field, field_validator

from app.schemas.explanation import ExplanationResult


class EmailAnalyzeRequest(BaseModel):
    email_text: str

    @field_validator("email_text")
    @classmethod
    def email_text_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("email_text must not be empty or whitespace only")
        return value


class EmailAnalyzeResponse(ExplanationResult):
    """Frontend-facing analysis result: explanation fields plus risk-engine signal families."""

    signal_families: list[str] = Field(default_factory=list)
