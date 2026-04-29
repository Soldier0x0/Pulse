"""Risk scoring for normalized threat events."""

from __future__ import annotations

from src.types import ThreatEvent


def calculate_risk_score(event: ThreatEvent, config: dict) -> float:
    """Calculate bounded risk score from base CVSS and source signals."""

    weights = config["scoring"]
    score = float(event.cvss)

    if event.signals.get("malwarebazaar"):
        score += float(weights.get("malwarebazaar_bonus", 2.0))
    if event.signals.get("otx"):
        score += float(weights.get("otx_bonus", 1.5))
    if event.signals.get("cisa_kev"):
        score += float(weights.get("cisa_kev_bonus", 1.0))
    if event.signals.get("exploitdb"):
        score += float(weights.get("exploitdb_bonus", 0.5))
    if event.signals.get("news"):
        score += float(weights.get("news_bonus", 0.5))

    return min(score, float(weights.get("max_score", 10.0)))


def severity_from_score(score: float) -> str:
    """Map numeric score to label."""

    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"
