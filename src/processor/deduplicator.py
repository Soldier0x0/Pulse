"""Mongo-backed deduplication and persistence for alerts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase


async def should_send_alert(db: AsyncIOMotorDatabase, alert_doc: dict[str, Any]) -> bool:
    """Check if an alert should be sent considering cooldown and severity escalation."""

    cve_id = alert_doc["cve_id"]
    severity = alert_doc["severity_label"]
    source_set = sorted(alert_doc.get("sources", []))
    cooldown_hours = int(alert_doc["metadata"].get("alert_cooldown_hours", 6))
    threshold = datetime.now(timezone.utc) - timedelta(hours=cooldown_hours)

    existing = await db.alerts.find_one(
        {"cve_id": cve_id, "sources": source_set, "created_at": {"$gte": threshold}},
        sort=[("created_at", -1)],
    )
    if not existing:
        return True

    old_sev = existing.get("severity_label", "low")
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return rank.get(severity, 0) > rank.get(old_sev, 0)


async def save_alert(db: AsyncIOMotorDatabase, alert_doc: dict[str, Any]) -> None:
    """Persist an alert document in MongoDB."""

    await db.alerts.insert_one(alert_doc)
