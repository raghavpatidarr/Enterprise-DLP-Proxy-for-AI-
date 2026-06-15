"""Tests for app.proxy — recursive JSON payload sanitization and
re-identification, mimicking OpenAI/Anthropic chat-completion shapes."""

import pytest

from app.pii_engine import pii_engine
from app.proxy import sanitize_payload, reidentify_payload


@pytest.fixture(scope="module", autouse=True)
def _warmup():
    pii_engine.warmup()


def test_sanitize_chat_completion_payload():
    payload = {
        "model": "gpt-4o",
        "temperature": 0.7,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "My email is jane.doe@acme.com, please summarize."},
        ],
    }

    sanitized, mapping = sanitize_payload(payload, session_id="sess-123")

    # Structural fields untouched
    assert sanitized["model"] == "gpt-4o"
    assert sanitized["temperature"] == 0.7

    user_content = sanitized["messages"][1]["content"]
    assert "jane.doe@acme.com" not in user_content
    assert len(mapping) == 1


def test_reidentify_chat_completion_response():
    mapping = {"[DLP_EMAIL_abcdef1234]": "jane.doe@acme.com"}
    response = {
        "id": "chatcmpl-123",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Sure, I'll send it to [DLP_EMAIL_abcdef1234] shortly.",
                }
            }
        ],
    }

    restored = reidentify_payload(response, mapping)
    restored_content = restored["choices"][0]["message"]["content"]

    assert "jane.doe@acme.com" in restored_content
    assert "[DLP_EMAIL_abcdef1234]" not in restored_content
    assert restored["id"] == "chatcmpl-123"


def test_sanitize_handles_nested_lists_and_non_text_fields():
    payload = {
        "model": "gpt-4o",
        "metadata": {"id": 123.45, "tags": ["alpha", "beta"]},
        "messages": [
            {"role": "user", "content": "Card 4111 1111 1111 1111 was declined."},
        ],
    }

    sanitized, mapping = sanitize_payload(payload, session_id="sess-456")

    assert sanitized["metadata"]["id"] == 123.45
    assert sanitized["metadata"]["tags"] == ["alpha", "beta"]
    assert "4111 1111 1111 1111" not in sanitized["messages"][0]["content"]
    assert len(mapping) == 1


def test_full_roundtrip_through_sanitize_and_reidentify():
    payload = {
        "messages": [
            {"role": "user", "content": "Contact John at john@acme.com about SSN 123-45-6789."}
        ]
    }

    sanitized, mapping = sanitize_payload(payload, session_id="sess-789")
    sanitized_content = sanitized["messages"][0]["content"]
    assert "john@acme.com" not in sanitized_content
    assert "123-45-6789" not in sanitized_content

    # Simulate an LLM response that echoes the tokens back
    fake_response = {"choices": [{"message": {"content": f"Got it, will email and reference SSN. ({sanitized_content})"}}]}
    restored = reidentify_payload(fake_response, mapping)
    restored_content = restored["choices"][0]["message"]["content"]

    assert "john@acme.com" in restored_content
    assert "123-45-6789" in restored_content
