"""
Payload-level sanitization / re-identification + upstream HTTP forwarding.

Designed to work generically against OpenAI/Anthropic-style chat-completion
payloads, but recurses through arbitrary JSON so it tolerates other shapes
(e.g. custom internal LLM gateways) without breaking.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import settings
from app.pii_engine import pii_engine

logger = logging.getLogger("dlp_proxy.proxy")

_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=settings.upstream_base_url,
            timeout=settings.upstream_timeout_seconds,
        )
    return _client


# ---------------------------------------------------------------------------
# Recursive payload sanitization
# ---------------------------------------------------------------------------
# Only these JSON keys are scanned for PII. This keeps structural fields
# (model names, ids, temperature, etc.) untouched and avoids tokenizing
# values that aren't free text.
TEXT_FIELDS = {"content", "text", "message", "prompt", "input", "system"}


def sanitize_payload(payload: Any, session_id: str) -> tuple[Any, dict[str, str]]:
    """
    Recursively walk a JSON-like structure, tokenizing PII found in text
    fields. Returns the sanitized structure and a merged mapping of all new
    token -> original_value pairs discovered (to be persisted to Redis).
    """
    merged_mapping: dict[str, str] = {}
    sanitized = _walk(payload, session_id, merged_mapping, sanitize=True)
    return sanitized, merged_mapping


def reidentify_payload(payload: Any, mapping: dict[str, str]) -> Any:
    """Recursively walk a JSON-like structure, replacing any DLP tokens with
    their original values using the provided session mapping."""
    return _walk(payload, session_id=None, mapping_out=mapping, sanitize=False)


def _walk(node: Any, session_id: str | None, mapping_out: dict[str, str], sanitize: bool) -> Any:
    if isinstance(node, dict):
        return {
            key: (_process_string(value, session_id, mapping_out, sanitize) if _is_text_field(key, value) else _walk(value, session_id, mapping_out, sanitize))
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_walk(item, session_id, mapping_out, sanitize) for item in node]
    return node


def _is_text_field(key: str, value: Any) -> bool:
    return isinstance(value, str) and key in TEXT_FIELDS


def _process_string(value: str, session_id: str | None, mapping_out: dict[str, str], sanitize: bool) -> str:
    if sanitize:
        sanitized_text, local_mapping = pii_engine.tokenize_text(value, session_id=session_id)  # type: ignore[arg-type]
        mapping_out.update(local_mapping)
        return sanitized_text
    return pii_engine.reidentify_text(value, mapping_out)


# ---------------------------------------------------------------------------
# Upstream forwarding
# ---------------------------------------------------------------------------
HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "x-dlp-session-id",
}


async def forward_request(method: str, path: str, json_body: dict, headers: dict[str, str]) -> httpx.Response:
    client = get_http_client()

    forward_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}

    if settings.upstream_api_key:
        forward_headers["Authorization"] = f"Bearer {settings.upstream_api_key}"

    request = client.build_request(method=method, url=path, json=json_body, headers=forward_headers)
    response = await client.send(request, stream=True)
    return response
