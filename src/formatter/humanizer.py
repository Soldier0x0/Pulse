"""Render structured alerts into channel-friendly text."""

from __future__ import annotations

from html import escape
import random

from src.formatter.templates import INTRO_PHRASES, SIGNOFF_PHRASES, URGENCY_PHRASES
from src.types import Alert


def render_telegram_html(alert: Alert) -> str:
    """Build HTML-formatted message for Telegram."""

    intro = random.choice(INTRO_PHRASES)
    urgency = random.choice(URGENCY_PHRASES)
    signoff = random.choice(SIGNOFF_PHRASES)
    mitre = ", ".join(alert.mitre_tags) if alert.mitre_tags else "N/A"
    sources = ", ".join(alert.sources)
    headline_target = alert.product if alert.product != "unknown" else (alert.cve_id or "threat")
    affected = f"{alert.product} {alert.version}".strip() if alert.product != "unknown" else "See description and CVE reference"

    return (
        f"🚨 <b>{escape(headline_target)}</b> alert (<b>{escape(alert.severity_label.upper())}</b>)\n\n"
        f"{escape(intro)} <b>{escape(headline_target)}</b>.\n"
        f"{escape(alert.summary)}\n\n"
        f"📦 <b>What's affected:</b> {escape(affected)}\n"
        f"🧷 <b>CVE:</b> <code>{escape(alert.cve_id)}</code>\n"
        f"💀 <b>Risk Score:</b> {alert.score:.1f}/10 ({escape(alert.severity_label)})\n"
        f"🌍 <b>Exploitation:</b> {escape(alert.exploitation_status)}\n"
        f"🎯 <b>ATT&CK:</b> {escape(mitre)}\n"
        f"📰 <b>Sources:</b> {escape(sources)}\n\n"
        f"⚡ <b>{escape(urgency)}</b>\n\n"
        f"{escape(signoff)}\n"
        f"🔗 {escape(alert.nvd_link)}"
    )


def render_telegram_markdown(alert: Alert) -> str:
    """Backward-compatible alias for HTML renderer."""

    return render_telegram_html(alert)
