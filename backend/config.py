"""
Configuration management using Pydantic Settings.
Reads from environment variables and .env files.
"""

import os
from typing import List, Optional

from pydantic_settings import BaseSettings
from pydantic import Field


def _flag(name: str, default: bool = False) -> bool:
    """Read a boolean environment flag."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class Settings(BaseSettings):
    """Application settings"""

    # Sarvam AI (optional)
    sarvam_api_key: Optional[str] = Field(None, env="SARVAM_API_KEY")

    # Backend
    backend_host: str = Field("0.0.0.0", env="BACKEND_HOST")
    backend_port: int = Field(8000, env="BACKEND_PORT")

    # Docker sandbox
    sandbox_image: str = Field("saferun-sandbox:latest", env="SANDBOX_IMAGE")

    # Database
    database_url: str = Field("sqlite:///./saferun.db", env="DATABASE_URL")

    # Policy
    policy_file: str = Field("backend/policies/default_policy.yaml", env="POLICY_FILE")

    # --- Authentication -------------------------------------------------
    # These are read with os.getenv so the variable names are explicit and
    # do not depend on how a given pydantic-settings version maps field
    # names to environment variables.
    #
    #   SAFERUN_API_KEYS        comma separated list of accepted API keys
    #   SAFERUN_ADMIN_KEY       enables override=true on blocked code
    #   SAFERUN_ALLOW_ANONYMOUS set to 1 for a throwaway local instance
    api_keys: Optional[str] = os.getenv("SAFERUN_API_KEYS")
    admin_key: Optional[str] = os.getenv("SAFERUN_ADMIN_KEY")
    allow_anonymous: bool = _flag("SAFERUN_ALLOW_ANONYMOUS")

    # --- Limits ---------------------------------------------------------
    # Cap on captured stdout/stderr per execution, and on how many
    # containers may run at the same time.
    max_output_bytes: int = int(os.getenv("SAFERUN_MAX_OUTPUT_BYTES", "65536"))
    max_concurrent_executions: int = int(os.getenv("SAFERUN_MAX_CONCURRENT", "4"))

    # Extra browser origins allowed to call the API. Empty means same-origin
    # only, which is what the bundled frontend needs.
    allowed_origins: Optional[str] = os.getenv("SAFERUN_ALLOWED_ORIGINS")

    @property
    def api_key_list(self) -> List[str]:
        """Parsed list of accepted API keys (empty when none configured)."""
        return [k.strip() for k in (self.api_keys or "").split(",") if k.strip()]

    @property
    def allowed_origin_list(self) -> List[str]:
        """Parsed list of CORS origins."""
        return [o.strip() for o in (self.allowed_origins or "").split(",") if o.strip()]

    class Config:
        env_file = ".env"
        env_file_config = "utf-8"
        case_sensitive = False


settings = Settings()
