"""HaveIBeenPwned breach collector."""

from __future__ import annotations

from typing import Any

import aiohttp

from src.types import ThreatEvent


async def fetch_hibp_events(config: dict[str, Any], api_key: str) -> list[ThreatEvent]:
    """Fetch latest HIBP breaches and normalize records."""

    source_cfg = config["sources"]["hibp"]
    if not source_cfg.get("enabled", True):
        return []
    headers = {"hibp-api-key": api_key, "user-agent": "cti-platform"}
    timeout = aiohttp.ClientTimeout(total=source_cfg.get("timeout_seconds", 20))
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        async with session.get(source_cfg["url"]) as response:
            if response.status >= 400:
                return []
            payload = await response.json()
    if isinstance(payload, dict):
        payload = payload.get("breaches", [])
    if not isinstance(payload, list):
        return []
    return [
        ThreatEvent(source="hibp", title=entry.get("Name", "breach"), description=entry.get("Description", ""))
        for entry in payload[:50]
    ]
