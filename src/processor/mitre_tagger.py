"""Keyword-based MITRE ATT&CK tagging."""

from __future__ import annotations


def tag_mitre(description: str, mapping: dict[str, str]) -> list[str]:
    """Return matching ATT&CK technique IDs for the given text."""

    lower_text = description.lower()
    tags: list[str] = []
    for keyword, technique in mapping.items():
        if keyword.lower() in lower_text and technique not in tags:
            tags.append(technique)
    return tags
