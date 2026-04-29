"""Lightweight classical classifier and entity extractor."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(slots=True)
class ClassificationResult:
    """Prediction output for vulnerability type."""

    label: str
    confidence: float


class ClassicalClassifier:
    """Bag-of-words multinomial model with fallback behavior."""

    def __init__(self) -> None:
        """Initialize model artifacts."""

        self.label_token_counts: dict[str, dict[str, int]] = {}
        self.label_totals: dict[str, int] = {}
        self.vocabulary: set[str] = set()
        self._trained = False

    def train(self, texts: list[str], labels: list[str]) -> None:
        """Train model from labeled examples."""

        for text, label in zip(texts, labels, strict=True):
            bucket = self.label_token_counts.setdefault(label, {})
            self.label_totals.setdefault(label, 0)
            for token in _tokenize(text):
                self.vocabulary.add(token)
                bucket[token] = bucket.get(token, 0) + 1
                self.label_totals[label] += 1
        self._trained = True

    def predict(self, text: str) -> ClassificationResult:
        """Predict label with confidence, fallback if untrained."""

        if not self._trained:
            return ClassificationResult(label=_keyword_label(text), confidence=0.35)
        scores: dict[str, float] = {}
        vocab_size = max(len(self.vocabulary), 1)
        tokens = _tokenize(text)
        for label, token_counts in self.label_token_counts.items():
            total = self.label_totals.get(label, 1)
            log_prob = 0.0
            for token in tokens:
                count = token_counts.get(token, 0)
                prob = (count + 1) / (total + vocab_size)  # Laplace smoothing.
                log_prob += math.log(prob)
            scores[label] = log_prob
        best_label = max(scores, key=scores.get)
        confidence = _softmax_confidence(scores, best_label)
        return ClassificationResult(label=best_label, confidence=confidence)


def extract_entities(text: str, dictionary: dict[str, list[str]]) -> dict[str, str]:
    """Extract vendor/product/version using dictionary + regex heuristics."""

    lower = text.lower()
    vendor = _pick_first(lower, dictionary.get("vendors", [])) or "unknown"
    product = _pick_first(lower, dictionary.get("products", [])) or "unknown"
    version_match = re.search(r"\b\d+\.\d+(?:\.\d+)?\b", text)
    version = version_match.group(0) if version_match else "unknown"
    return {"vendor": vendor, "product": product, "version": version}


def _pick_first(text: str, candidates: list[str]) -> str | None:
    """Return first matching candidate in text."""

    for item in candidates:
        if item.lower() in text:
            return item
    return None


def _keyword_label(text: str) -> str:
    """Infer vulnerability class from keywords."""

    t = text.lower()
    if "sql" in t and "inject" in t:
        return "sqli"
    if "privilege" in t:
        return "privesc"
    if "denial of service" in t or "dos" in t:
        return "dos"
    if "bypass" in t and "auth" in t:
        return "authbypass"
    if "information disclosure" in t or "info leak" in t:
        return "infoleak"
    return "rce" if "remote code execution" in t else "unknown"


def _tokenize(text: str) -> list[str]:
    """Tokenize plain text for simple language modeling."""

    return re.findall(r"[a-zA-Z0-9_]+", text.lower())


def _softmax_confidence(scores: dict[str, float], winner: str) -> float:
    """Convert log-scores to bounded confidence."""

    max_score = max(scores.values())
    shifted = {label: math.exp(score - max_score) for label, score in scores.items()}
    total = sum(shifted.values()) or 1.0
    return shifted[winner] / total
