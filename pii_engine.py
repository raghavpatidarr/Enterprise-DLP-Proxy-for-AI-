"""
PII detection and tokenization engine.

Combines:
  - Regex patterns for structured PII (emails, phone numbers, SSNs, credit
    cards, IP addresses, API keys, IBANs, etc.) — high precision, deterministic.
  - spaCy NER for unstructured PII (PERSON, ORG, GPE/LOC) — handles names and
    entities that regex cannot reliably catch.

Detected entities are replaced with deterministic, collision-resistant tokens
of the form: [<LABEL>_<hash>]. The same (session, original_value) pair always
maps to the same token, so repeated mentions of "John Smith" within one
request are tokenized consistently.
"""

from __future__ import annotations

import hashlib
import logging
import re

import spacy
from spacy.language import Language

from app.config import settings
from app.schemas import PIIEntity

logger = logging.getLogger("dlp_proxy.pii_engine")


# ---------------------------------------------------------------------------
# Regex patterns for structured PII
# ---------------------------------------------------------------------------
# Ordered: more specific patterns first to avoid partial overlaps (e.g. a
# credit card number shouldn't also be partially matched as a phone number).
REGEX_PATTERNS: dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "IPV4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"),
    "PHONE": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "API_KEY": re.compile(r"\b(?:sk|pk|rk|api|key)[-_][A-Za-z0-9]{16,}\b", re.IGNORECASE),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "DATE_OF_BIRTH": re.compile(r"\b(0[1-9]|1[0-2])[/-](0[1-9]|[12]\d|3[01])[/-](19|20)\d{2}\b"),
}

# spaCy entity labels we consider sensitive enough to tokenize.
NER_LABELS_OF_INTEREST = {
    "PERSON": "PERSON",
    "ORG": "ORG",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "NORP": "GROUP",
    "FAC": "FACILITY",
}


class PIIEngine:
    """Stateless detection + tokenization. Per-session mappings live in Redis."""

    def __init__(self) -> None:
        self._nlp: Language | None = None
        self.model_name = settings.spacy_model

    def warmup(self) -> None:
        """Load the spaCy model eagerly at startup to avoid first-request latency."""
        if not settings.enable_ner:
            logger.info("NER disabled via config; skipping spaCy model load.")
            return
        try:
            self._nlp = spacy.load(self.model_name)
            logger.info("Loaded spaCy model '%s'", self.model_name)
        except OSError:
            logger.warning(
                "spaCy model '%s' not found. Run: python -m spacy download %s. "
                "Falling back to regex-only detection.",
                self.model_name,
                self.model_name,
            )
            self._nlp = None

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------
    def detect(self, text: str) -> list[PIIEntity]:
        entities: list[PIIEntity] = []

        if settings.enable_regex:
            entities.extend(self._detect_regex(text))

        if settings.enable_ner and self._nlp is not None:
            entities.extend(self._detect_ner(text))

        return self._resolve_overlaps(entities)

    def _detect_regex(self, text: str) -> list[PIIEntity]:
        found: list[PIIEntity] = []
        for label, pattern in REGEX_PATTERNS.items():
            for match in pattern.finditer(text):
                found.append(
                    PIIEntity(
                        text=match.group(),
                        label=label,
                        start=match.start(),
                        end=match.end(),
                        source="regex",
                        confidence=1.0,
                    )
                )
        return found

    def _detect_ner(self, text: str) -> list[PIIEntity]:
        found: list[PIIEntity] = []
        doc = self._nlp(text)
        for ent in doc.ents:
            mapped_label = NER_LABELS_OF_INTEREST.get(ent.label_)
            if mapped_label is None:
                continue
            found.append(
                PIIEntity(
                    text=ent.text,
                    label=mapped_label,
                    start=ent.start_char,
                    end=ent.end_char,
                    source="ner",
                    confidence=0.85,
                )
            )
        return found

    def _resolve_overlaps(self, entities: list[PIIEntity]) -> list[PIIEntity]:
        """Sort by start position; on overlap, prefer regex (deterministic)
        over NER, and longer spans over shorter ones."""
        entities.sort(key=lambda e: (e.start, -(e.end - e.start)))

        resolved: list[PIIEntity] = []
        last_end = -1
        for ent in entities:
            if ent.start >= last_end:
                resolved.append(ent)
                last_end = ent.end
            else:
                # Overlaps the previous entity; keep regex over NER if conflict.
                prev = resolved[-1]
                if ent.source == "regex" and prev.source == "ner" and ent.start < prev.end:
                    resolved[-1] = ent
                    last_end = ent.end
        return resolved

    # ------------------------------------------------------------------
    # Tokenization / re-identification
    # ------------------------------------------------------------------
    def make_token(self, value: str, label: str, session_id: str) -> str:
        """Deterministic token: same (session, value, label) -> same token."""
        digest = hashlib.sha256(f"{session_id}:{label}:{value}".encode("utf-8")).hexdigest()[:10]
        return f"[{settings.token_prefix}_{label}_{digest}]"

    def tokenize_text(self, text: str, session_id: str) -> tuple[str, dict[str, str]]:
        """
        Replace all detected PII in `text` with tokens.

        Returns:
            (sanitized_text, mapping) where mapping is {token: original_value}.
        """
        entities = self.detect(text)
        if not entities:
            return text, {}

        mapping: dict[str, str] = {}
        # Replace from the end of the string backwards so earlier offsets stay valid.
        sanitized = text
        for ent in sorted(entities, key=lambda e: e.start, reverse=True):
            token = self.make_token(ent.text, ent.label, session_id)
            mapping[token] = ent.text
            sanitized = sanitized[: ent.start] + token + sanitized[ent.end :]

        return sanitized, mapping

    def reidentify_text(self, text: str, mapping: dict[str, str]) -> str:
        """Replace any DLP tokens present in `text` with their original values."""
        if not mapping or not text:
            return text

        # Sort by token length descending to avoid partial-token collisions.
        for token in sorted(mapping.keys(), key=len, reverse=True):
            if token in text:
                text = text.replace(token, mapping[token])
        return text


pii_engine = PIIEngine()
