from typing import List, Optional
from pydantic import BaseModel, Field


class AIInputPayload(BaseModel):
    subject: str
    from_address: str
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    body_text_preview: str
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_domains: List[str] = Field(default_factory=list)
    detected_indicator_ids: List[str] = Field(default_factory=list)


class AIOutputPayload(BaseModel):
    available: bool = False
    provider_name: str = "none"
    classification: Optional[str] = None
    confidence: float = 0.0
    social_engineering_signals: List[str] = Field(default_factory=list)
    reasoning: List[str] = Field(default_factory=list)
    status_message: str = "AI enrichment unavailable — deterministic analysis used."
