from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load .env file before Settings is instantiated
load_dotenv(override=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Required
    anthropic_api_key: str = ""

    # Custom API base URL (for third-party providers like SiliconFlow)
    anthropic_base_url: str = ""

    # API format: "anthropic" or "openai" (for OpenAI-compatible providers)
    api_format: str = "anthropic"

    # Proxy — http or socks5, configure one (e.g. http://127.0.0.1:7890 or socks5://127.0.0.1:7890)
    http_proxy: str = ""

    # Optional data source keys
    nvd_api_key: str = ""
    github_token: str = ""

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/ti.db"

    # Encryption
    secrets_encryption_key: str = ""

    # Model and cost
    anthropic_model: str = "baidu/cobuddy:free"
    monthly_budget_usd: float = 50.0
    monthly_budget_cny: float = 300.0
    single_task_token_limit: int = 900_000

    # Agent config
    researcher_count_default: int = 4
    researcher_max_rounds: int = 2
    enrichment_timeout_s: int = 15
    synthesis_timeout_s: int = 120
    analysis_timeout_s: int = 600

    # Data directories
    data_dir: str = "./data"
    attck_bundle_path: str = "./data/attck/enterprise-attack.json"

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # Server
    host: str = "127.0.0.1"
    port: int = 8000

    @property
    def data_dir_path(self) -> Path:
        return Path(self.data_dir)

    @property
    def attck_bundle_file(self) -> Path:
        return Path(self.attck_bundle_path)


settings = Settings()
