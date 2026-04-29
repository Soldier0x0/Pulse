"""Configuration loaders for environment and YAML settings."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


class EnvSettings:
    """Environment-backed secret settings."""

    def __init__(self) -> None:
        """Load all environment-backed settings."""

        self.mongo_uri = os.getenv("MONGO_URI", "mongodb://mongodb:27017")
        self.mongo_db = os.getenv("MONGO_DB", "cti")
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "replace_me")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "replace_me")
        self.discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "replace_me")
        self.nvd_api_key = os.getenv("NVD_API_KEY", "replace_me")
        self.otx_api_key = os.getenv("OTX_API_KEY", "replace_me")
        self.hibp_api_key = os.getenv("HIBP_API_KEY", "replace_me")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "replace_me")
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "replace_me")


@lru_cache(maxsize=1)
def get_env_settings() -> EnvSettings:
    """Return singleton env settings."""

    return EnvSettings()


@lru_cache(maxsize=1)
def load_config(path: str = "config.yml") -> dict[str, Any]:
    """Load YAML config into a dictionary."""

    cfg_path = Path(path)
    with cfg_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}
