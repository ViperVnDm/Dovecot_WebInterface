"""Application configuration management."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    secret_key: str = "change-me-in-production"
    debug: bool = False
    app_name: str = "Mail Server Admin"

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/admin.db"

    # Session
    session_expire_hours: int = 24
    session_cookie_name: str = "session"

    # Mail server paths
    mail_log_path: Path = Path("/var/log/mail.log")
    mail_spool_path: Path = Path("/var/mail")
    postfix_queue_path: Path = Path("/var/spool/postfix")

    # Privileged helper
    helper_socket_path: Path = Path("/run/dovecot-webadmin/helper.sock")

    # Rate limiting
    login_rate_limit: str = "5/minute"

    # Security
    bcrypt_rounds: int = 12


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
