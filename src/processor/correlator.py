"""Cross-source correlation engine."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from src.types import ThreatEvent


def correlate_by_product(events: list[ThreatEvent], min_sources: int = 3, within_hours: int = 24) -> dict[str, list[ThreatEvent]]:
    """Group product-targeting evidence across sources in a time window."""

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=within_hours)
    buckets: dict[str, list[ThreatEvent]] = defaultdict(list)
    for event in events:
        if event.published_at >= cutoff:
            buckets[event.product.lower()].append(event)

    correlated: dict[str, list[ThreatEvent]] = {}
    for product, rows in buckets.items():
        source_count = len({row.source for row in rows})
        if source_count >= min_sources and product != "unknown":
            correlated[product] = rows
    return correlated
