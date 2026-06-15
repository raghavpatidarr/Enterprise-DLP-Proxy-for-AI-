"""Request/response models for the DLP proxy's own API endpoints."""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    redis: bool
    ner_model: str
    upstream: str


class TokenizeRequest(BaseModel):
    text: str = Field(..., description="Raw text potentially containing PII.")
    session_id: str = Field(..., description="Session id used to scope the token mapping in Redis.")
    ttl_seconds: int | None = Field(default=None, description="Override default TTL for this mapping.")


class TokenizeResponse(BaseModel):
    sanitized_text: str
    entities_found: int
    tokens: list[str]


class ReidentifyRequest(BaseModel):
    text: str = Field(..., description="Text containing DLP tokens to restore.")
    session_id: str = Field(..., description="Session id whose mapping should be used.")


class ReidentifyResponse(BaseModel):
    restored_text: str
    tokens_replaced: int


class PIIEntity(BaseModel):
    text: str
    label: str
    start: int
    end: int
    source: str  # "regex" | "ner"
    confidence: float = 1.0
