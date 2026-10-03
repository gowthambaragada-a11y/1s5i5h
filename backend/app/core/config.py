"""Application settings.

All secrets are sourced from environment variables (or a local ``.env``).
Nothing sensitive is ever hard-coded -- see ``Settings.secret_key`` below.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # ---- Application -----------------------------------------------------
    app_name: str = "NETGUARD-AI"
    environment: Literal["dev", "staging", "prod"] = "dev"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # ---- Security --------------------------------------------------------
    # MUST be overridden in any non-dev deployment. Validated in __post_init__.
    secret_key: str = Field(default="dev-only-insecure-key-change-me", min_length=16)
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 60
    # The built-in operator accounts exist so the demo works with no database.
    # They are a fixed set of published passwords, so they must not survive into
    # a public deployment: anyone who reads the repository could otherwise log
    # in as an admin. See `_reject_demo_accounts_in_prod`.
    allow_demo_accounts: bool = True
    # Argon2id parameters for the local operator accounts.
    pwd_hash_time_cost: int = 3
    pwd_hash_memory_cost_kib: int = 64_536

    # Uploads are untrusted input: cap size, restrict suffixes, never trust filename.
    max_upload_bytes: int = 10 * 1024 * 1024
    allowed_upload_suffixes: frozenset[str] = frozenset(
        {".cfg", ".conf", ".config", ".txt", ".running", ".saved", ".json", ".xml"}
    )

    # ---- PostgreSQL ------------------------------------------------------
    postgres_dsn: str = "postgresql+psycopg://netguard:netguard@localhost:5432/netguard"
    db_echo: bool = False
    db_pool_size: int = 5
    db_max_overflow: int = 10

    # ---- Neo4j (Security Knowledge Graph) --------------------------------
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    # Left blank by default so no credential is baked into the repository.
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"
    # Graph enrichment is optional: the pipeline degrades gracefully without it.
    graph_enabled: bool = True

    # ---- LLM (optional NLP / remediation) --------------------------------
    llm_enabled: bool = False
    llm_provider: Literal["anthropic", "openai", "ollama", "mock"] = "mock"
    llm_model: str = "claude-sonnet-5"
    llm_api_key: str | None = None
    llm_base_url: str | None = None
    llm_timeout_seconds: float = 30.0
    llm_max_retries: int = 2
    # Never let an LLM response execute; commands require human approval anyway,
    # but we also structurally validate before persisting.
    llm_temperature: float = 0.0

    # ---- Analysis tuning --------------------------------------------------
    anomaly_contamination: float = Field(default=0.05, gt=0.0, lt=0.5)
    anomaly_min_samples: int = 25

    # Read from the environment as a JSON array, e.g.
    #   CORS_ORIGINS='["https://example.github.io"]'
    # pydantic-settings JSON-decodes complex-typed fields *before* any validator
    # runs, so a comma-separated value here aborts startup with a JSONDecodeError
    # rather than reaching `_split_origins`. The validator below still handles
    # comma-separated strings passed directly to the constructor.
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @model_validator(mode="after")
    def _reject_dev_secrets_in_prod(self) -> Settings:
        """A prod deployment must not run on the committed placeholder values.

        Checked here rather than in a field validator because a field validator
        only sees fields declared *before* it, and `environment` is declared first
        -- so a per-field check would silently never see `secret_key` and would
        never fire.
        """
        if self.environment == "prod" and self.secret_key.startswith("dev-only"):
            raise ValueError("secret_key must be set from the environment when environment=prod")
        return self

    @model_validator(mode="after")
    def _reject_demo_accounts_in_prod(self) -> Settings:
        """A public deployment must not ship the built-in operator passwords.

        They are deliberately weak and documented, so leaving them enabled on a
        public URL is the same as leaving a default admin password in place. The
        failure is at startup rather than at first login, so it cannot be missed
        once the service is already serving.
        """
        if self.environment == "prod" and self.allow_demo_accounts:
            raise ValueError(
                "allow_demo_accounts must be false when environment=prod; "
                "the built-in admin/analyst/viewer passwords are public"
            )
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "prod"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached accessor so env is parsed once per process."""
    return Settings()
