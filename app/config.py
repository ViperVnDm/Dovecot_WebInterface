"""Application configuration management."""

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_SECRET_KEY = "change-me-in-production"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    secret_key: str = DEFAULT_SECRET_KEY
    debug: bool = False
    app_name: str = "Mail Server Admin"

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/admin.db"

    # Session
    session_expire_hours: int = 24
    session_cookie_name: str = "dwa_session"
    csrf_cookie_name: str = "dwa_csrf"

    # Mail server paths
    mail_log_path: Path = Path("/var/log/mail.log")
    mail_spool_path: Path = Path("/var/mail")
    postfix_queue_path: Path = Path("/var/spool/postfix")

    # Privileged helper
    helper_socket_path: Path = Path("/run/dovecot-webadmin/helper.sock")

    # SMTP for alert notifications (defaults to local Postfix)
    smtp_host: str = "localhost"
    smtp_port: int = 25
    smtp_from: str = ""  # Must be set in .env, e.g. alerts@yourdomain.com

    # Rate limiting
    login_rate_limit: str = "5/minute"

    # Security
    bcrypt_rounds: int = 12
    cookie_secure: bool = True

    @field_validator("secret_key")
    @classmethod
    def _check_secret_key(cls, v: str, info) -> str:
        # Reject the default placeholder unless we are running in debug mode.
        # Pydantic v2 validators don't see other field values reliably, so
        # we re-check `debug` from the raw env at runtime.
        import os
        debug_env = os.environ.get("DEBUG", "false").lower() in ("1", "true", "yes")
        if v == DEFAULT_SECRET_KEY and not debug_env:
            raise ValueError(
                "SECRET_KEY must be set to a unique value in production. "
                "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        if len(v) < 16:
            raise ValueError("SECRET_KEY must be at least 16 characters")
        return v


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
