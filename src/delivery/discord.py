"""Discord webhook delivery implementation."""

from __future__ import annotations

from discord_webhook import DiscordEmbed, DiscordWebhook

from src.types import Alert

VENDOR_THUMBNAILS = {
    "microsoft": "https://www.microsoft.com/favicon.ico",
    "apache": "https://www.apache.org/favicons/favicon-32x32.png",
    "oracle": "https://www.oracle.com/a/ocom/img/favicon.ico",
    "vmware": "https://www.vmware.com/etc.clientlibs/vmware/clientlibs/clientlib-base/resources/images/favicon.ico",
    "d-link": "https://www.dlink.com/favicon.ico",
    "samsung": "https://www.samsung.com/etc.clientlibs/samsung/clientlibs/clientlib-site/resources/favicon.ico",
}


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
    title_target = alert.product if alert.product != "unknown" else alert.cve_id
    embed = DiscordEmbed(
        title=f"{title_target} threat alert",
        description=alert.summary,
        color=_color_for_severity(alert.severity_label),
    )
    if alert.nvd_link:
        embed.url = alert.nvd_link
    vendor_key = (alert.vendor or "").lower()
    thumbnail = VENDOR_THUMBNAILS.get(vendor_key)
    if thumbnail and hasattr(embed, "set_thumbnail"):
        embed.set_thumbnail(url=thumbnail)
    embed.add_embed_field(name="Risk Score", value=f"{alert.score:.1f}/10", inline=True)
    embed.add_embed_field(name="Severity", value=alert.severity_label, inline=True)
    embed.add_embed_field(name="CVE", value=alert.cve_id, inline=True)
    embed.add_embed_field(name="Product", value=alert.product, inline=True)
    embed.add_embed_field(name="Vendor", value=alert.vendor, inline=True)
    embed.add_embed_field(name="Version", value=alert.version, inline=True)
    embed.add_embed_field(name="Exploitation", value=alert.exploitation_status, inline=False)
    embed.add_embed_field(name="ATT&CK", value=", ".join(alert.mitre_tags) or "N/A", inline=False)
    embed.add_embed_field(name="Sources", value=", ".join(alert.sources), inline=False)
    if hasattr(embed, "set_timestamp"):
        embed.set_timestamp()
    embed.set_footer(text="Pulse CTI")
    webhook.add_embed(embed)
    webhook.execute()
