"""Tests for risk scoring."""

from src.processor.scorer import calculate_risk_score, severity_from_score
from src.types import ThreatEvent


def test_score_with_bonus() -> None:
    cfg = {"scoring": {"malwarebazaar_bonus": 2.0, "max_score": 10.0}}
    event = ThreatEvent(source="x", title="x", description="x", cvss=8.0, signals={"malwarebazaar": True})
    assert calculate_risk_score(event, cfg) == 10.0


def test_severity_mapping() -> None:
    assert severity_from_score(9.1) == "critical"
