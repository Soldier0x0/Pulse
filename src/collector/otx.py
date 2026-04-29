"""AlienVault OTX collector."""

from __future__ import annotations

from typing import Any

import aiohttp

from src.types import ThreatEvent


async def fetch_otx_events(config: dict[str, Any], api_key: str) -> list[ThreatEvent]:
    """Fetch OTX pulses and return normalized events."""

    source_cfg = config["sources"]["otx"]
    if not source_cfg.get("enabled", True):
        return []
    headers = {"X-OTX-API-KEY": api_key}
    timeout = aiohttp.ClientTimeout(total=source_cfg.get("timeout_seconds", 20))
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        async with session.get(source_cfg["url"]) as response:
            if response.status >= 400:
                return []
            payload = await response.json()
    events: list[ThreatEvent] = []
    for pulse in payload.get("results", []):
        title = pulse.get("name", "OTX pulse")
        desc = pulse.get("description", "")
        events.append(ThreatEvent(source="otx", title=title, description=desc, signals={"otx": True}))
    return events
