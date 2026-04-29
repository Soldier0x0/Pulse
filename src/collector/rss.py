"""Generic RSS collector for analyst/news feeds."""

from __future__ import annotations

from typing import Any

import aiohttp
import feedparser

from src.types import ThreatEvent


async def fetch_rss_events(config: dict[str, Any]) -> list[ThreatEvent]:
    """Fetch and normalize entries from configured RSS feeds."""

    source_cfg = config["sources"]["rss"]
    if not source_cfg.get("enabled", True):
        return []
    timeout = aiohttp.ClientTimeout(total=source_cfg.get("timeout_seconds", 20))
    all_events: list[ThreatEvent] = []
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for feed_url in source_cfg.get("feeds", []):
            try:
                async with session.get(feed_url) as response:
                    if response.status >= 400:
                        continue
                    content = await response.text()
                feed = feedparser.parse(content)
                for entry in feed.entries[:30]:
                    all_events.append(
                        ThreatEvent(
                            source="rss",
                            title=entry.get("title", "news"),
                            description=entry.get("summary", ""),
                            references=[entry.get("link", "")],
                            signals={"news": True},
                        )
                    )
            except Exception:  # noqa: BLE001
                continue
    return all_events
