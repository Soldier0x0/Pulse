"""Weekly digest generation utilities."""

from __future__ import annotations

from collections import Counter


def build_weekly_digest(alerts: list[dict]) -> str:
    """Build newsletter-style weekly digest from alerts."""

    severity_counts = Counter(alert.get("severity_label", "unknown") for alert in alerts)
    products = Counter(alert.get("product", "unknown") for alert in alerts)
    mitre = Counter(tag for alert in alerts for tag in alert.get("mitre_tags", []))

    top_products = ", ".join([name for name, _ in products.most_common(5)]) or "none"
    top_mitre = ", ".join([name for name, _ in mitre.most_common(5)]) or "none"
    critical_count = severity_counts.get("critical", 0)

    return (
        "This week the CTI stream captured a sustained flow of vulnerability and exploitation signals. "
        f"Critical alerts totaled {critical_count}, while high and medium trends remained active across monitored technologies. "
        f"The most targeted products were {top_products}. ATT&CK patterns were led by {top_mitre}. "
        "Response teams should focus on patch acceleration, external exposure validation, and abuse telemetry checks."
    )
