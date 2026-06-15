# Enterprise DLP Proxy for AI

A FastAPI-based **Data Loss Prevention (DLP) reverse proxy** for outbound LLM
traffic. It sits between your internal applications and an external LLM API
(OpenAI/Anthropic-compatible), automatically:

1. **Detecting PII** in outbound prompts using a combination of **Regex**
   (emails, phone numbers, SSNs, credit cards, IPs, API keys, AWS keys, IBANs,
   dates of birth) and **spaCy NER** (person names, organizations, locations,
   nationalities/groups, facilities).
2. **Tokenizing** each detected entity into a deterministic placeholder like
   `[DLP_PERSON_a1b2c3d4e5]` and storing the `token -> original_value` mapping
   in **Redis**, scoped to a session and protected by a TTL.
3. **Forwarding** the sanitized payload to the upstream LLM — the model never
   sees real PII.
4. **Re-identifying** any tokens that appear in the LLM's response (including
   streamed SSE responses) by swapping them back to the original values
   before returning to the caller — so the *end user* sees normal, readable
   text while the *third-party model* never did.

This gives you zero-trust outbound privacy compliance with minimal added
latency, since detection/tokenization happens in-process and Redis lookups
are O(1) hash reads.

## Architecture

```
┌────────────┐      ┌─────────────────────────────────────────┐      ┌──────────────┐
│   Internal │ ───► │              DLP Proxy                   │ ───► │  Upstream    │
│   Client   │      │  1. Detect PII (Regex + spaCy NER)       │      │  LLM API     │
│            │ ◄─── │  2. Tokenize -> store mapping in Redis   │ ◄─── │ (OpenAI etc) │
└────────────┘      │  3. Forward sanitized request            │      └──────────────┘
                     │  4. Re-identify tokens in the response   │
                     │  5. Return readable response to client   │
                     └─────────────────┬─────────────────────────┘
                                         │
                                         ▼
                                  ┌─────────────┐
                                  │    Redis    │
                                  │ token <-> PII│
                                  │  (per session,│
                                  │   TTL-bound)  │
                                  └─────────────┘
```

## Quickstart

### 1. Configure environment

```bash
cp .env.example .env
# edit .env: set DLP_UPSTREAM_BASE_URL and DLP_UPSTREAM_API_KEY
```

### 2. Run with Docker Compose

```bash
docker compose up --build
```

This starts:
- `redis` — token mapping store
- `dlp-proxy` — the FastAPI app on `http://localhost:8000`

### 3. Run locally (without Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# start Redis separately, e.g.:
docker run -p 6379:6379 redis:7-alpine

uvicorn app.main:app --reload
```

## Usage

### Proxy a chat completion request

Send your normal chat-completion request to the proxy instead of directly to
the upstream provider. The proxy mirrors the upstream's path structure under
`/v1/...`.

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-DLP-Session-Id: user-42-session" \
  -d '{
        "model": "gpt-4o",
        "messages": [
          {"role": "user", "content": "Draft a follow-up email to jane.doe@acme.com about her account, SSN 123-45-6789."}
        ]
      }'
```

What happens internally:
- `jane.doe@acme.com` -> `[DLP_EMAIL_xxxxxxxxxx]`
- `123-45-6789` -> `[DLP_SSN_xxxxxxxxxx]`
- The sanitized prompt is sent to the real LLM.
- If the LLM's reply echoes either token back, the proxy swaps it back to the
  real value before the response reaches you.

If you omit `X-DLP-Session-Id`, the proxy generates one and returns it via the
`X-DLP-Session-Id` response header (with `X-DLP-New-Session: true`) — capture
it and reuse it for subsequent turns in the same conversation so entities
tokenized earlier can still be re-identified later.

### Standalone tokenize / reidentify endpoints

Useful for testing or for integrating the DLP engine into other pipelines
without doing a full LLM round trip.

```bash
# Tokenize
curl -X POST http://localhost:8000/v1/tokenize \
  -H "Content-Type: application/json" \
  -d '{"text": "Call John Smith at 415-555-0132.", "session_id": "demo"}'

# Reidentify
curl -X POST http://localhost:8000/v1/reidentify \
  -H "Content-Type: application/json" \
  -d '{"text": "Got it, will call [DLP_PERSON_xxxxxxxxxx] at [DLP_PHONE_xxxxxxxxxx].", "session_id": "demo"}'
```

### Health check

```bash
curl http://localhost:8000/healthz
```

## Configuration

All configuration is via environment variables (prefix `DLP_`), see
`.env.example`:

| Variable | Default | Description |
|---|---|---|
| `DLP_UPSTREAM_BASE_URL` | `https://api.openai.com` | Base URL of the real LLM API |
| `DLP_UPSTREAM_API_KEY` | — | API key injected as `Authorization: Bearer ...` when forwarding |
| `DLP_UPSTREAM_TIMEOUT_SECONDS` | `60` | Upstream request timeout |
| `DLP_REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `DLP_TOKEN_TTL_SECONDS` | `3600` | TTL for a session's token mapping |
| `DLP_SESSION_HEADER` | `X-DLP-Session-Id` | Header used to correlate requests into a session |
| `DLP_SPACY_MODEL` | `en_core_web_sm` | spaCy model used for NER |
| `DLP_ENABLE_NER` | `true` | Toggle NER-based detection |
| `DLP_ENABLE_REGEX` | `true` | Toggle regex-based detection |
| `DLP_LOG_LEVEL` | `INFO` | Logging level |
| `DLP_TOKEN_PREFIX` | `DLP` | Prefix used in generated tokens |

## Detected PII Types

| Source | Labels |
|---|---|
| Regex | `EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `IBAN`, `IPV4`, `API_KEY`, `AWS_ACCESS_KEY`, `DATE_OF_BIRTH` |
| spaCy NER | `PERSON`, `ORG`, `LOCATION` (GPE/LOC), `GROUP` (NORP), `FACILITY` (FAC) |

Regex matches take priority over overlapping NER matches to keep tokenization
deterministic and structured PII intact.

## Testing

```bash
pip install pytest
pytest tests/ -v
```

## Security Notes

- Redis mappings are TTL-bound (default 1 hour) — extend `DLP_TOKEN_TTL_SECONDS`
  for long-running conversations, or persist mappings to a more durable store
  for compliance audit trails if required.
- The proxy strips inbound `Authorization` headers from clients and injects
  its own configured `DLP_UPSTREAM_API_KEY`, so client apps never need direct
  access to the upstream provider's credentials.
- Only JSON fields named `content`, `text`, `message`, `prompt`, `input`, or
  `system` are scanned/tokenized (see `app/proxy.py: TEXT_FIELDS`) — extend
  this set if your payload shape uses different field names.

## Project Structure

```
.
├── app/
│   ├── main.py          # FastAPI app, routes, proxy orchestration
│   ├── config.py         # Settings (env-driven)
│   ├── schemas.py         # Pydantic models
│   ├── pii_engine.py       # Regex + NER detection, tokenize/reidentify
│   ├── redis_client.py      # Session-scoped Redis mapping store
│   └── proxy.py             # Recursive payload sanitization + HTTP forwarding
├── tests/
│   ├── test_pii_engine.py
│   └── test_proxy.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── README.md
```

## License

MIT
