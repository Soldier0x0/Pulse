"""Tests for weekly digest formatter."""

from src.formatter.digest import build_weekly_digest


def test_digest_has_summary() -> None:
    txt = build_weekly_digest([{"severity_label": "critical", "product": "apache", "mitre_tags": ["T1059"]}])
    assert "Critical alerts totaled" in txt
