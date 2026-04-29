"""CISA KEV collector."""

from __future__ import annotations

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
        events.append(
            ThreatEvent(
                source="cisa_kev",
                title=cve_id,
                description=row.get("shortDescription", ""),
                cve_ids=[cve_id] if cve_id else [],
                cvss=7.0,
                signals={"cisa_kev": True},
            )
        )
    return events
