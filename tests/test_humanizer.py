"""Tests for alert humanizer."""

from src.formatter.humanizer import render_telegram_markdown
from src.types import Alert


def test_render_contains_score() -> None:
    alert = Alert(
        schema_version="alert_v1",
        cve_id="CVE-2026-0001",
        product="apache",
        vendor="apache",
        version="2.4.59",
        score=9.5,
        severity_label="critical",
        mitre_tags=["T1059"],
        sources=["nvd"],
        exploitation_status="active",
        summary="Test summary",
        nvd_link="https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
    )
    text = render_telegram_markdown(alert)
    assert "Risk Score: 9.5/10" in text
