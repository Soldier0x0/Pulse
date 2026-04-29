"""APScheduler jobs for polling and digest delivery."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from motor.motor_asyncio import AsyncIOMotorDatabase

from src.delivery.discord import send_discord_alert
from src.delivery.telegram import send_telegram_alert
from src.formatter.digest import build_weekly_digest
from src.main import run_once


def build_scheduler(timezone_name: str) -> AsyncIOScheduler:
    """Create scheduler with configured timezone."""

    return AsyncIOScheduler(timezone=timezone_name)


def register_jobs(
    scheduler: AsyncIOScheduler,
    db: AsyncIOMotorDatabase,
    poll_interval_minutes: int,
    telegram_token: str,
    telegram_chat_id: str,
    discord_webhook_url: str,
) -> None:
    """Register ingestion loop and weekly digest jobs."""

    scheduler.add_job(run_once, "interval", minutes=poll_interval_minutes, id="polling")
    scheduler.add_job(
        _weekly_digest_job,
        "cron",
        day_of_week="mon",
        hour=9,
        minute=0,
        args=[db, telegram_token, telegram_chat_id, discord_webhook_url],
        id="weekly_digest",
    )


async def _weekly_digest_job(
    db: AsyncIOMotorDatabase,
    telegram_token: str,
    telegram_chat_id: str,
    discord_webhook_url: str,
) -> None:
    """Compile weekly digest and deliver to channels."""

    since = datetime.now(timezone.utc) - timedelta(days=7)
    alerts = await db.alerts.find({"created_at": {"$gte": since}}).to_list(length=5000)
    digest = build_weekly_digest(alerts)
    if telegram_token != "replace_me" and telegram_chat_id != "replace_me":
        await send_telegram_alert(telegram_token, telegram_chat_id, digest)
    if discord_webhook_url != "replace_me":
        from src.types import Alert

        alert = Alert(
            schema_version="alert_v1",
            cve_id="WEEKLY-DIGEST",
            product="CTI Weekly Digest",
            vendor="internal",
            version="n/a",
            score=0.0,
            severity_label="medium",
            mitre_tags=[],
            sources=["digest"],
            exploitation_status="weekly summary",
            summary=digest,
            nvd_link="",
        )
        send_discord_alert(discord_webhook_url, alert)
