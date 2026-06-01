from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApplicationSettings(BaseSettings):
    """Application configuration loaded from environment variables.

    All sensitive values are expected from the environment and are never hardcoded
    in the source. The configuration file is intentionally strict so production
    deployments fail fast when required values are missing.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
        validate_assignment=True,
    )

    # Application runtime and infrastructure.
    database_url: str = Field(..., validation_alias="DATABASE_URL")
    debug: bool = Field(default=False, validation_alias="DEBUG")

    # Authentication and authorization.
    jwt_secret_key: str = Field(..., min_length=32, validation_alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", validation_alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, ge=1, validation_alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, ge=1, validation_alias="REFRESH_TOKEN_EXPIRE_DAYS")

    # AWS infrastructure placeholders.
    aws_access_key_id: str | None = Field(default=None, validation_alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: str | None = Field(default=None, validation_alias="AWS_SECRET_ACCESS_KEY")
    aws_region: str = Field(default="us-east-1", validation_alias="AWS_REGION")

    # CloudWatch and SNS integration.
    cloudwatch_log_group_name: str = Field(
        default="cloud-threat-detection-system",
        validation_alias="CLOUDWATCH_LOG_GROUP_NAME",
    )
    sns_topic_arn: str = Field(default="", validation_alias="SNS_TOPIC_ARN")

    @property
    def database_dsn(self) -> str:
        """Return the configured database connection string."""

        return self.database_url

    @property
    def jwt_expiration_seconds(self) -> int:
        """Return the access token lifetime in seconds."""

        return self.access_token_expire_minutes * 60


settings = ApplicationSettings()

__all__ = ["ApplicationSettings", "settings"]
