"""
Enterprise DLP Proxy for AI
----------------------------
A FastAPI reverse proxy that sits between internal clients and an upstream
LLM API (e.g. OpenAI / Anthropic compatible). It:

1. Intercepts outbound prompts, detects PII via Regex + spaCy NER.
2. Tokenizes detected entities (e.g. "John Smith" -> "[PERSON_a1b2c3]").
3. Stores a bidirectional mapping (token <-> original value) in Redis,
   scoped to a session, with a TTL.
4. Forwards the sanitized payload to the upstream LLM.
5. Re-identifies tokens found in the LLM's response using the same
   session mapping before returning the response to the client.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from app.config import settings
from app.redis_client import redis_client
from app.pii_engine import pii_engine
from app.schemas import HealthResponse, TokenizeRequest, TokenizeResponse, ReidentifyRequest, ReidentifyResponse
from app.proxy import forward_request, sanitize_payload, reidentify_payload

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("dlp_proxy")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting DLP Proxy | upstream=%s", settings.upstream_base_url)
    pii_engine.warmup()
    await redis_client.ping()
    yield
    await redis_client.close()
    logger.info("Shut down DLP Proxy")


app = FastAPI(
    title="Enterprise DLP Proxy for AI",
    description="Intercepts, tokenizes, and re-identifies PII in LLM traffic.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/healthz", response_model=HealthResponse, tags=["ops"])
async def health() -> HealthResponse:
    redis_ok = await redis_client.healthcheck()
    return HealthResponse(
        status="ok" if redis_ok else "degraded",
        redis=redis_ok,
        ner_model=pii_engine.model_name,
        upstream=settings.upstream_base_url,
    )


@app.post("/v1/tokenize", response_model=TokenizeResponse, tags=["dlp"])
async def tokenize(req: TokenizeRequest) -> TokenizeResponse:
    """Tokenize raw text without forwarding anywhere. Useful for testing/debugging."""
    sanitized, mapping = pii_engine.tokenize_text(req.text, session_id=req.session_id)
    if mapping:
        await redis_client.store_mapping(req.session_id, mapping, ttl=req.ttl_seconds)
    return TokenizeResponse(sanitized_text=sanitized, entities_found=len(mapping), tokens=list(mapping.keys()))


@app.post("/v1/reidentify", response_model=ReidentifyResponse, tags=["dlp"])
async def reidentify(req: ReidentifyRequest) -> ReidentifyResponse:
    """Re-identify tokens in arbitrary text using a session's stored mapping."""
    mapping = await redis_client.get_mapping(req.session_id)
    restored = pii_engine.reidentify_text(req.text, mapping)
    return ReidentifyResponse(restored_text=restored, tokens_replaced=sum(1 for t in mapping if t in req.text))


@app.api_route(
    "/v1/{full_path:path}",
    methods=["POST"],
    tags=["proxy"],
)
async def proxy_llm(request: Request, full_path: str):
    """
    Generic reverse-proxy endpoint. Sanitizes the request body, forwards it to
    the configured upstream LLM endpoint, then re-identifies the response body
    before returning it to the caller.

    The session is identified via the `X-DLP-Session-Id` header. If absent, a
    new session id is generated and returned in the response headers.
    """
    started = time.perf_counter()
    body = await request.json()

    session_id = request.headers.get(settings.session_header, None)
    new_session = session_id is None
    if new_session:
        session_id = redis_client.new_session_id()

    sanitized_body, mapping_delta = sanitize_payload(body, session_id)

    if mapping_delta:
        await redis_client.store_mapping(session_id, mapping_delta, ttl=settings.token_ttl_seconds)

    upstream_path = f"/{full_path}"
    upstream_response = await forward_request(
        method="POST",
        path=upstream_path,
        json_body=sanitized_body,
        headers=dict(request.headers),
    )

    content_type = upstream_response.headers.get("content-type", "")

    if "text/event-stream" in content_type:
        full_mapping = await redis_client.get_mapping(session_id)
        return StreamingResponse(
            reidentify_stream(upstream_response, full_mapping),
            status_code=upstream_response.status_code,
            media_type="text/event-stream",
            headers=_passthrough_headers(upstream_response, session_id, new_session),
        )

    response_json = upstream_response.json()
    full_mapping = await redis_client.get_mapping(session_id)
    reidentified_json = reidentify_payload(response_json, full_mapping)

    elapsed_ms = (time.perf_counter() - started) * 1000
    logger.info(
        "session=%s path=%s pii_entities=%d latency_ms=%.2f",
        session_id,
        upstream_path,
        len(mapping_delta),
        elapsed_ms,
    )

    return JSONResponse(
        content=reidentified_json,
        status_code=upstream_response.status_code,
        headers=_passthrough_headers(upstream_response, session_id, new_session),
    )


async def reidentify_stream(upstream_response: httpx.Response, mapping: dict[str, str]):
    """Re-identify tokens within a streamed SSE response, chunk by chunk."""
    async for chunk in upstream_response.aiter_bytes():
        text = chunk.decode("utf-8", errors="ignore")
        restored = pii_engine.reidentify_text(text, mapping)
        yield restored.encode("utf-8")


def _passthrough_headers(upstream_response: httpx.Response, session_id: str, new_session: bool) -> dict:
    headers = {settings.session_header: session_id}
    if new_session:
        headers["X-DLP-New-Session"] = "true"
    return headers
