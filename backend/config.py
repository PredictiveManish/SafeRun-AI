"""
Configuration management using Pydantic Settings.
Reads from environment variables and .env files.
"""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


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

    class Config:
        env_file = ".env"
        env_file_config = "utf-8"
        case_sensitive = False


settings = Settings()
