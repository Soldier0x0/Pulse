"""Optional API app placeholder (deferred phase)."""

from __future__ import annotations

from src.api.routes import health


def app() -> dict[str, str]:
    """Return placeholder app payload."""

    return {"status": "deferred", "health": health()["status"]}
