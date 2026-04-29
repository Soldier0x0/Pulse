"""Tests for classical classifier and extraction."""

from src.processor.classifier import ClassicalClassifier, extract_entities


def test_classifier_predicts_after_train() -> None:
    clf = ClassicalClassifier()
    clf.train(
        ["remote code execution in service", "sql injection in endpoint", "privilege escalation bug"],
        ["rce", "sqli", "privesc"],
    )
    result = clf.predict("new remote code execution issue")
    assert result.label in {"rce", "sqli", "privesc"}


def test_entity_extraction() -> None:
    entities = extract_entities(
        "Microsoft Windows 10.2 has a security flaw",
        {"vendors": ["microsoft"], "products": ["windows"]},
    )
    assert entities["vendor"] == "microsoft"
    assert entities["product"] == "windows"
