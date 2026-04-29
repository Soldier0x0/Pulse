"""CTI platform entrypoint orchestrating collectors and deliveries."""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from motor.motor_asyncio import AsyncIOMotorClient

from src.collector.cisa_kev import fetch_cisa_kev_events
from src.collector.exploitdb import fetch_exploitdb_events
from src.collector.hibp import fetch_hibp_events
from src.collector.malwarebazaar import fetch_malwarebazaar_events
from src.collector.nvd import fetch_nvd_events
from src.collector.otx import fetch_otx_events
from src.collector.rss import fetch_rss_events
from src.delivery.discord import send_discord_alert
from src.delivery.telegram import send_telegram_alert
from src.formatter.humanizer import render_telegram_html
from src.processor.deduplicator import save_alert, should_send_alert
from src.processor.filter import filter_events
from src.processor.mitre_tagger import tag_mitre
from src.processor.scorer import calculate_risk_score, severity_from_score
from src.settings import get_env_settings, load_config
from src.types import Alert

LOGGER = logging.getLogger("cti")
logging.basicConfig(level=logging.INFO)


async def run_once() -> None:
    """Run one ingestion-processing-delivery pass."""

    cfg = load_config()
    env = get_env_settings()

    client = AsyncIOMotorClient(env.mongo_uri)
    db = client[env.mongo_db]

    collectors: list[tuple[str, Callable[[], Awaitable[list[Any]]]]] = [
        ("nvd", lambda: fetch_nvd_events(cfg, api_key=env.nvd_api_key)),
        ("otx", lambda: fetch_otx_events(cfg, env.otx_api_key)),
        ("malwarebazaar", lambda: fetch_malwarebazaar_events(cfg)),
        ("hibp", lambda: fetch_hibp_events(cfg, env.hibp_api_key)),
        ("cisa_kev", lambda: fetch_cisa_kev_events(cfg)),
        ("exploitdb", lambda: fetch_exploitdb_events(cfg)),
        ("rss", lambda: fetch_rss_events(cfg)),
    ]
    batches = await asyncio.gather(*[_fetch_with_retries(name, fn) for name, fn in collectors], return_exceptions=True)
    raw_events = []
    source_failures = 0
    for batch in batches:
        if isinstance(batch, Exception):
            source_failures += 1
            continue
        raw_events.extend(batch)

    filtered = filter_events(raw_events, cfg)
    filtered = await _apply_live_only_window(db, filtered, cfg)
    sent_count = 0
    dedup_dropped = 0
    max_alerts = int(cfg["filters"].get("max_alerts_per_cycle", 5))
    for event in filtered:
        if sent_count >= max_alerts:
            break
        cve_id = event.cve_ids[0] if event.cve_ids else "NO-CVE"
        score = calculate_risk_score(event, cfg)
        if event.published_at.year < datetime.now(timezone.utc).year - 1 and not _has_exploitation_signal(event):
            score = max(score - 2.0, 0.0)
        severity = severity_from_score(score)
        mitre_tags = tag_mitre(event.description, cfg["mitre_mapping"])
        confidence, enrichment = _enrichment_quality(event, mitre_tags)
        alert = Alert(
            schema_version="alert_v1",
            cve_id=cve_id,
            product=event.product,
            vendor=event.vendor,
            version=event.version,
            score=score,
            severity_label=severity,
            mitre_tags=mitre_tags,
            sources=[event.source],
            exploitation_status="active signals observed" if score >= 8.0 else "under observation",
            summary=event.description[:300] or event.title,
            nvd_link=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != "NO-CVE" else "",
            created_at=datetime.now(timezone.utc),
            metadata={
                "alert_cooldown_hours": cfg["filters"].get("alert_cooldown_hours", 6),
                "confidence": confidence,
                "enrichment_level": enrichment,
            },
        )
        doc = asdict(alert)
        doc["sources"] = sorted(doc["sources"])
        if await should_send_alert(db, doc):
            if not _in_quiet_hours(cfg):
                text = render_telegram_html(alert)
                pin = severity == "critical"
                if env.telegram_bot_token != "replace_me" and env.telegram_chat_id != "replace_me":
                    await send_telegram_alert(env.telegram_bot_token, env.telegram_chat_id, text, pin=pin)
                if env.discord_webhook_url != "replace_me":
                    send_discord_alert(env.discord_webhook_url, alert)
            await save_alert(db, doc)
            sent_count += 1
        else:
            dedup_dropped += 1

    if len(filtered) > max_alerts and env.telegram_bot_token != "replace_me" and env.telegram_chat_id != "replace_me":
        await send_telegram_alert(
            env.telegram_bot_token,
            env.telegram_chat_id,
            f"Cycle limited to {max_alerts} alerts. {len(filtered) - max_alerts} additional matches were suppressed.",
            pin=False,
        )
    LOGGER.info(
        "Pipeline counters fetched=%d filtered=%d sent=%d dedup_dropped=%d source_failures=%d",
        len(raw_events),
        len(filtered),
        sent_count,
        dedup_dropped,
        source_failures,
    )


async def run_forever() -> None:
    """Run continuous polling loop."""

    cfg = load_config()
    poll_minutes = int(cfg["runtime"].get("poll_interval_minutes", 5))
    while True:
        try:
            await run_once()
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Pipeline cycle failed: %s", exc)
        await asyncio.sleep(poll_minutes * 60)


if __name__ == "__main__":
    asyncio.run(run_forever())


async def _fetch_with_retries(name: str, fn: Callable[[], Awaitable[list[Any]]], retries: int = 3) -> list[Any]:
    """Fetch source payload with retry/backoff and isolated failures."""

    for attempt in range(1, retries + 1):
        try:
            return await fn()
        except Exception as exc:  # noqa: BLE001
            if attempt == retries:
                LOGGER.warning("Source %s failed after retries: %s", name, exc)
                return []
            delay = (2 ** (attempt - 1)) + random.uniform(0.1, 0.7)
            await asyncio.sleep(delay)
    return []


def _has_exploitation_signal(event: Any) -> bool:
    """Return true when event indicates likely active exploitation."""

    return bool(
        event.signals.get("malwarebazaar")
        or event.signals.get("cisa_kev")
        or event.signals.get("exploitdb")
        or event.signals.get("otx")
    )


def _in_quiet_hours(config: dict[str, Any]) -> bool:
    """Check quiet-hours suppression from config."""

    start = int(config["runtime"].get("quiet_hours_start", 0))
    end = int(config["runtime"].get("quiet_hours_end", 0))
    if start == end:
        return False
    hour = datetime.now().hour
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _enrichment_quality(event: Any, mitre_tags: list[str]) -> tuple[float, str]:
    """Compute enrichment confidence and quality label."""

    confidence = 0.35
    if event.product != "unknown":
        confidence += 0.25
    if event.vendor != "unknown":
        confidence += 0.15
    if mitre_tags:
        confidence += 0.15
    if event.cvss >= 7.0:
        confidence += 0.1
    confidence = min(confidence, 0.99)
    level = "high" if confidence >= 0.75 else "medium" if confidence >= 0.5 else "low"
    return confidence, level


async def _apply_live_only_window(db: Any, events: list[Any], config: dict[str, Any]) -> list[Any]:
    """Keep only events published after last successful run timestamp."""

    if not bool(config["runtime"].get("live_only_mode", True)):
        return events
    now = datetime.now(timezone.utc)
    state = await db.pipeline_state.find_one({"_id": "live_window"})
    if not state:
        # First startup in live mode should not backfill historical data.
        await db.pipeline_state.update_one(
            {"_id": "live_window"},
            {"$set": {"last_run_at": now}},
            upsert=True,
        )
        LOGGER.info("Live-only mode initialized; skipping backlog on first run.")
        return []
    last_run_at = state.get("last_run_at", now)
    if last_run_at.tzinfo is None:
        last_run_at = last_run_at.replace(tzinfo=timezone.utc)
    recent = []
    for event in events:
        published_at = event.published_at
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=timezone.utc)
        if published_at >= last_run_at:
            recent.append(event)
    await db.pipeline_state.update_one(
        {"_id": "live_window"},
        {"$set": {"last_run_at": now}},
        upsert=True,
    )
    return recent
