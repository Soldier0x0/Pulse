"""Render structured alerts into channel-friendly text."""

from __future__ import annotations

import random

from src.formatter.templates import INTRO_PHRASES, SIGNOFF_PHRASES, URGENCY_PHRASES
from src.types import Alert


def render_telegram_markdown(alert: Alert) -> str:
    """Build markdown message for Telegram."""

    intro = random.choice(INTRO_PHRASES)
    urgency = random.choice(URGENCY_PHRASES)
    signoff = random.choice(SIGNOFF_PHRASES)
    mitre = ", ".join(alert.mitre_tags) if alert.mitre_tags else "N/A"
    sources = ", ".join(alert.sources)

    return (
        f"🚨 *{alert.product}* alert ({alert.severity_label.upper()})\n\n"
        f"{intro} *{alert.product}*.\n"
        f"{alert.summary}\n\n"
        f"📦 What's affected: {alert.product} {alert.version}\n"
        f"💀 Risk Score: {alert.score:.1f}/10 ({alert.severity_label})\n"
        f"🌍 Exploitation: {alert.exploitation_status}\n"
        f"🎯 ATT&CK: {mitre}\n"
        f"📰 Sources: {sources}\n\n"
        f"⚡ {urgency}\n\n"
        f"{signoff}\n"
        f"🔗 {alert.nvd_link}"
    )
