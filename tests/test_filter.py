"""Tests for filtering logic."""

from src.processor.filter import filter_events
from src.types import ThreatEvent


def test_filter_keeps_high_cvss() -> None:
    cfg = {"filters": {"min_cvss_score": 7.0, "watch_keywords": [], "watch_cve_ids": [], "watch_products": []}}
    events = [ThreatEvent(source="nvd", title="CVE-1", description="desc", cvss=9.0)]
    assert len(filter_events(events, cfg)) == 1
