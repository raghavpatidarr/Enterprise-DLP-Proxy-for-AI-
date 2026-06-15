"""Unit tests for app.pii_engine — regex detection, NER detection, and
round-trip tokenize/reidentify."""

import pytest

from app.pii_engine import PIIEngine


@pytest.fixture(scope="module")
def engine() -> PIIEngine:
    e = PIIEngine()
    e.warmup()
    return e


# ---------------------------------------------------------------------------
# Regex detection
# ---------------------------------------------------------------------------
def test_detects_email(engine: PIIEngine):
    entities = engine.detect("Contact me at jane.doe@acme.com for details.")
    labels = {e.label for e in entities}
    assert "EMAIL" in labels


def test_detects_phone(engine: PIIEngine):
    entities = engine.detect("Call me at 415-555-0132 tomorrow.")
    labels = {e.label for e in entities}
    assert "PHONE" in labels


def test_detects_ssn(engine: PIIEngine):
    entities = engine.detect("SSN on file: 123-45-6789")
    labels = {e.label for e in entities}
    assert "SSN" in labels


def test_detects_credit_card(engine: PIIEngine):
    entities = engine.detect("Card number 4111 1111 1111 1111 was charged.")
    labels = {e.label for e in entities}
    assert "CREDIT_CARD" in labels


def test_detects_aws_key(engine: PIIEngine):
    entities = engine.detect("Key: AKIAIOSFODNN7EXAMPLE leaked in repo")
    labels = {e.label for e in entities}
    assert "AWS_ACCESS_KEY" in labels


# ---------------------------------------------------------------------------
# NER detection (skips gracefully if spaCy model isn't installed)
# ---------------------------------------------------------------------------
def test_detects_person_name(engine: PIIEngine):
    if engine._nlp is None:
        pytest.skip("spaCy model not installed in this environment")
    entities = engine.detect("John Smith joined the call from Acme Corp.")
    labels = {e.label for e in entities}
    assert "PERSON" in labels


# ---------------------------------------------------------------------------
# Tokenization round-trip
# ---------------------------------------------------------------------------
def test_tokenize_and_reidentify_roundtrip(engine: PIIEngine):
    text = "Please email jane.doe@acme.com regarding invoice 123-45-6789."
    session_id = "test-session-1"

    sanitized, mapping = engine.tokenize_text(text, session_id=session_id)

    assert "jane.doe@acme.com" not in sanitized
    assert "123-45-6789" not in sanitized
    assert len(mapping) == 2

    restored = engine.reidentify_text(sanitized, mapping)
    assert restored == text


def test_tokenize_is_deterministic_per_session(engine: PIIEngine):
    text = "Email jane.doe@acme.com twice: jane.doe@acme.com again."
    sanitized, mapping = engine.tokenize_text(text, session_id="determinism-test")

    # Same value -> same token, so the mapping should have exactly 1 entry
    # even though the email appears twice.
    assert len(mapping) == 1

    token = next(iter(mapping))
    assert sanitized.count(token) == 2


def test_no_pii_returns_original_text(engine: PIIEngine):
    text = "The weather is nice today and the meeting starts at noon."
    sanitized, mapping = engine.tokenize_text(text, session_id="no-pii-session")
    assert sanitized == text
    assert mapping == {}


def test_token_format(engine: PIIEngine):
    text = "Reach me at jane.doe@acme.com"
    sanitized, mapping = engine.tokenize_text(text, session_id="format-test")
    token = next(iter(mapping))
    assert token.startswith("[DLP_EMAIL_")
    assert token.endswith("]")
