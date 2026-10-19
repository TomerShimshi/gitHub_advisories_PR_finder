"""Runtime settings, read from environment variables (compose passes them in from .env)."""

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    # SECURITY: tokens live only in the environment and are wrapped in SecretStr so they never
    # end up in logs or reprs. With more time: load from a secret manager and require a
    # fine-grained, read-only GitHub token.
    github_token: SecretStr | None = Field(default=None, alias="GITHUB_TOKEN")
    openrouter_api_key: SecretStr | None = Field(default=None, alias="OPENROUTER_API_KEY")

    github_api_url: str = Field(default="https://api.github.com", alias="GITHUB_API_URL")
    cache_dir: Path = Field(default=Path("cache"), alias="CACHE_DIR")
    output_dir: Path = Field(default=Path("output"), alias="OUTPUT_DIR")
    # Advisory listings change over time, so they expire; immutable data (commits) won't.
    advisory_cache_ttl_hours: float = Field(default=24.0, alias="ADVISORY_CACHE_TTL_HOURS")
    http_timeout_seconds: float = Field(default=30.0, alias="HTTP_TIMEOUT_SECONDS")
    http_max_retries: int = Field(default=3, alias="HTTP_MAX_RETRIES")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # LLMs (via OpenRouter). Pinned versions, never "~latest" aliases, so results are repeatable.
    openrouter_base_url: str = Field(
        default="https://openrouter.ai/api/v1", alias="OPENROUTER_BASE_URL"
    )
    investigator_model: str = Field(
        # V4.1 Flash missed jinja and mcp (judge: insufficient evidence); V4 Pro got both.
        default="deepseek/deepseek-v4-pro", alias="INVESTIGATOR_MODEL"
    )
    judge_model: str = Field(default="anthropic/claude-opus-5.5", alias="JUDGE_MODEL")
    # Hard caps in US dollars: the run stops cleanly (keeping results so far) when reached.
    budget_usd: float = Field(default=5.0, alias="BUDGET_USD")
    advisory_budget_usd: float = Field(default=0.50, alias="ADVISORY_BUDGET_USD")
    # Tool calls the investigator may make per advisory.
    tool_call_budget: int = Field(default=20, alias="TOOL_CALL_BUDGET")
