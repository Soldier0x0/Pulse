"""Shared data models for CTI pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ThreatEvent:
    """Normalized raw threat event from any collector."""

    source: str
    title: str
    description: str
    cve_ids: list[str] = field(default_factory=list)
    product: str = "unknown"
    vendor: str = "unknown"
    version: str = "unknown"
    cvss: float = 0.0
    references: list[str] = field(default_factory=list)
    published_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signals: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Alert:
    """Structured alert saved and sent to channels."""

    schema_version: str
    cve_id: str
    product: str
    vendor: str
    version: str
    score: float
    severity_label: str
    mitre_tags: list[str]
    sources: list[str]
    exploitation_status: str
    summary: str
    nvd_link: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
