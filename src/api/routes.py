"""Optional API route placeholders for future UI integration."""

from __future__ import annotations

def health() -> dict[str, str]:
    """Return service health status."""

    return {"status": "ok"}
