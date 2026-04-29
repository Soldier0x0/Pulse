"""Tests for correlation engine."""

from datetime import datetime, timezone

from src.processor.correlator import correlate_by_product
from src.types import ThreatEvent


def test_correlation_threshold() -> None:
    now = datetime.now(timezone.utc)
    rows = [
        ThreatEvent(source="nvd", title="a", description="x", product="apache", published_at=now),
        ThreatEvent(source="rss", title="b", description="x", product="apache", published_at=now),
        ThreatEvent(source="otx", title="c", description="x", product="apache", published_at=now),
    ]
    out = correlate_by_product(rows, min_sources=3)
    assert "apache" in out
