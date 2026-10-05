"""
Waymark — AI-Native Reconnaissance Platform

Application configuration via environment variables with pydantic-settings.
All settings can be overridden via a .env file or system environment variables.
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# Resolve absolute path to the project root .env file
ROOT_DIR = Path(__file__).parent.parent.parent
ENV_PATH = ROOT_DIR / ".env"

# Force load the .env file into os.environ so non-pydantic scripts (like llm_assist.py) can read it
load_dotenv(dotenv_path=ENV_PATH)

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=str(ENV_PATH),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://waymark:waymark_dev_secret@localhost:5432/waymark"
    database_url_sync: str = "postgresql://waymark:waymark_dev_secret@localhost:5432/waymark"

    # ── Redis ─────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Auth (JWT) ────────────────────────────────────────────────────
    jwt_secret: str = "waymark-dev-jwt-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # ── Application ───────────────────────────────────────────────────
    debug: bool = True
    app_name: str = "Waymark"
    app_version: str = "0.1.0"
    log_level: str = "INFO"

    # ── Scan Defaults ─────────────────────────────────────────────────
    default_scan_timeout: int = 300       # 5 min per tool
    default_rate_limit: int = 25          # requests/sec for active tools (Tier 3 governor default)
    default_top_n_targets: int = 10       # deep-scan top N scored subdomains
    max_concurrent_tool_runs: int = 2     # arq worker concurrency (key lightweight governor)
    wordlist_storage_path: str = "data/wordlists"

    # ── Proxy Integration ─────────────────────────────────────────────
    enable_burp_proxy: bool = False
    burp_proxy_url: str = "http://127.0.0.1:8080"


settings = Settings()

