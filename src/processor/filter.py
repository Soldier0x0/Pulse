"""Filtering logic for CVSS and watchlists."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.types import ThreatEvent


def filter_events(events: list[ThreatEvent], config: dict) -> list[ThreatEvent]:
    """Filter events based on score and watchlist criteria."""

    rules = config["filters"]
    min_cvss = float(rules.get("min_cvss_score", 7.0))
    keywords = [k.lower() for k in rules.get("watch_keywords", [])]
    watch_cves = {c.upper() for c in rules.get("watch_cve_ids", [])}
    watch_products = {p.lower() for p in rules.get("watch_products", [])}
    recency_days = int(rules.get("recency_days", 90))
    cutoff = datetime.now(timezone.utc) - timedelta(days=recency_days)

    kept: list[ThreatEvent] = []
    for event in events:
        published_at = event.published_at
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=timezone.utc)
        text = f"{event.title} {event.description}".lower()
        is_score_match = event.cvss >= min_cvss
        is_keyword_match = any(keyword in text for keyword in keywords)
        is_cve_match = any(cve.upper() in watch_cves for cve in event.cve_ids)
        is_product_match = event.product.lower() in watch_products
        is_recent = published_at >= cutoff

        if is_cve_match or is_product_match:
            kept.append(event)
            continue

        # Require both relevance and freshness for non-watchlist alerts.
        if is_recent and (is_score_match or is_keyword_match):
            kept.append(event)
    return kept
