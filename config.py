"""Centralized configuration loaded from environment variables / .env file."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="DLP_", extra="ignore")

    # --- Upstream LLM provider ---
    upstream_base_url: str = "https://api.openai.com"
    upstream_api_key: str | None = None
    upstream_timeout_seconds: float = 60.0

    # --- Redis (token <-> PII mapping store) ---
    redis_url: str = "redis://localhost:6379/0"
    token_ttl_seconds: int = 3600  # 1 hour default TTL for token mappings

    # --- Session handling ---
    session_header: str = "X-DLP-Session-Id"

    # --- PII detection ---
    spacy_model: str = "en_core_web_sm"
    enable_ner: bool = True
    enable_regex: bool = True
    min_confidence: float = 0.5

    # --- Misc ---
    log_level: str = "INFO"
    token_prefix: str = "DLP"


settings = Settings()
