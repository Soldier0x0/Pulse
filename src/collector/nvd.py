"""NVD collector that fetches CVEs and normalizes events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import aiohttp

from src.types import ThreatEvent


async def fetch_nvd_events(config: dict[str, Any], api_key: str = "replace_me") -> list[ThreatEvent]:
    """Fetch CVEs from NVD API and return normalized events."""

    source_cfg = config["sources"]["nvd"]
    params = {"resultsPerPage": 100}
    timeout = aiohttp.ClientTimeout(total=source_cfg.get("timeout_seconds", 20))

    headers: dict[str, str] = {}
    if api_key and api_key != "replace_me":
        headers["apiKey"] = api_key

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        async with session.get(source_cfg["url"], params=params) as response:
            response.raise_for_status()
            payload = await response.json()

    events: list[ThreatEvent] = []
    for item in payload.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        description = _extract_description(cve_data)
        cvss = _extract_cvss(cve_data)
        vendor, product, version = _extract_cpe_identity(cve_data)
        references = [ref.get("url", "") for ref in cve_data.get("references", []) if ref.get("url")]
        events.append(
            ThreatEvent(
                source="nvd",
                title=cve_id,
                description=description,
                cve_ids=[cve_id] if cve_id else [],
                vendor=vendor,
                product=product,
                version=version,
                cvss=cvss,
                references=references,
                published_at=_extract_published_at(cve_data),
                signals={"nvd": True},
            )
        )
    return events


def _extract_description(cve_data: dict[str, Any]) -> str:
    """Extract best available NVD description text."""

    descriptions = cve_data.get("descriptions", [])
    for row in descriptions:
        if row.get("lang") == "en":
            return row.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _extract_cvss(cve_data: dict[str, Any]) -> float:
    """Extract CVSS v3/v2 score from NVD payload."""

    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return 0.0


def _extract_cpe_identity(cve_data: dict[str, Any]) -> tuple[str, str, str]:
    """Extract vendor/product/version from NVD CPE configurations."""

    configs = cve_data.get("configurations", [])
    for conf in configs:
        for node in conf.get("nodes", []):
            identity = _extract_from_node(node)
            if identity:
                return identity
    return "unknown", "unknown", "unknown"


def _extract_from_node(node: dict[str, Any]) -> tuple[str, str, str] | None:
    """Recursively extract vendor/product/version from CPE match nodes."""

    for match in node.get("cpeMatch", []):
        cpe = match.get("criteria", "")
        parts = cpe.split(":")
        if len(parts) >= 6:
            vendor = parts[3] or "unknown"
            product = parts[4] or "unknown"
            version = parts[5] if parts[5] not in ("*", "-") else "unknown"
            if version == "unknown":
                version = (
                    match.get("versionStartIncluding")
                    or match.get("versionStartExcluding")
                    or match.get("versionEndIncluding")
                    or match.get("versionEndExcluding")
                    or "unknown"
                )
            return vendor, product, version
    for child in node.get("children", []):
        identity = _extract_from_node(child)
        if identity:
            return identity
    return None


def _extract_published_at(cve_data: dict[str, Any]) -> datetime:
    """Extract published timestamp from NVD payload."""

    published = cve_data.get("published", "")
    if published:
        try:
            parsed = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            pass
    return datetime.now(timezone.utc)
