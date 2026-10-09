from typing import Optional

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    category: str
    severity: float = Field(ge=0.0, le=1.0)
    reason: str
    observed_value: Optional[str] = None
    source: str
