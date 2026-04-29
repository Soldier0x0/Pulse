"""Discord webhook delivery implementation."""

from __future__ import annotations

from discord_webhook import DiscordEmbed, DiscordWebhook

from src.types import Alert


def _color_for_severity(label: str) -> str:
    """Map severity to embed color hex."""

    if label == "critical":
        return "FF0000"
    if label == "high":
        return "FF8C00"
    return "FFD700"


def send_discord_alert(webhook_url: str, alert: Alert) -> None:
    """Send alert to Discord using colored embed."""

    webhook = DiscordWebhook(url=webhook_url, rate_limit_retry=True)
    embed = DiscordEmbed(
        title=f"{alert.product} threat alert",
        description=alert.summary,
        color=_color_for_severity(alert.severity_label),
    )
    embed.add_embed_field(name="Risk Score", value=f"{alert.score:.1f}/10", inline=True)
    embed.add_embed_field(name="Severity", value=alert.severity_label, inline=True)
    embed.add_embed_field(name="ATT&CK", value=", ".join(alert.mitre_tags) or "N/A", inline=False)
    embed.add_embed_field(name="Sources", value=", ".join(alert.sources), inline=False)
    embed.set_footer(text=alert.nvd_link)
    webhook.add_embed(embed)
    webhook.execute()
