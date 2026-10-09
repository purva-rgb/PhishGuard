from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ParsedEmail(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_: Optional[str] = Field(default=None, alias="from")
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    received: list[str] = Field(default_factory=list)
    authentication_results: Optional[str] = None
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"
    plain_text_body: Optional[str] = None
    html_body: Optional[str] = None
