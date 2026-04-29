"""Tests for MITRE tagger."""

from src.processor.mitre_tagger import tag_mitre


def test_mitre_keyword_match() -> None:
    tags = tag_mitre("remote code execution and privilege escalation", {"remote code execution": "T1059", "privilege escalation": "T1068"})
    assert "T1059" in tags and "T1068" in tags
