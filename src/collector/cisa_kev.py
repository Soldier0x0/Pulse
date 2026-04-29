"""CISA KEV collector."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import aiohttp

from src.types import ThreatEvent


async def fetch_cisa_kev_events(config: dict[str, Any]) -> list[ThreatEvent]:
    """Fetch CISA Known Exploited Vulnerabilities feed."""

    source_cfg = config["sources"]["cisa_kev"]
    if not source_cfg.get("enabled", True):
        return []
    timeout = aiohttp.ClientTimeout(total=source_cfg.get("timeout_seconds", 20))
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(source_cfg["url"]) as response:
            if response.status >= 400:
                return []
            payload = await response.json(content_type=None)
    events: list[ThreatEvent] = []
    for row in payload.get("vulnerabilities", []):
        cve_id = row.get("cveID", "")
        vendor = row.get("vendorProject", "unknown") or "unknown"
        product = row.get("product", "unknown") or "unknown"
        description = row.get("shortDescription", "")
        events.append(
            ThreatEvent(
                source="cisa_kev",
                title=cve_id,
                description=description,
                cve_ids=[cve_id] if cve_id else [],
                vendor=vendor.lower(),
                product=product.lower(),
                cvss=7.0,
                published_at=_parse_date(row.get("dateAdded", "")),
                signals={"cisa_kev": True},
            )
        )
    return events


def _parse_date(value: str) -> datetime:
    """Parse CISA KEV date field to timezone-aware datetime."""

    if value:
        try:
            return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)
