"""Database models and connection management."""

from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import String, Integer, Boolean, DateTime, Text, ForeignKey, BigInteger, Float, UniqueConstraint, Index
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.config import get_settings

settings = get_settings()


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


class AdminUser(Base):
    """Admin users for web console authentication."""

    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    sessions: Mapped[list["Session"]] = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    """User sessions."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("admin_users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped["AdminUser"] = relationship("AdminUser", back_populates="sessions")


class AlertRule(Base):
    """Alert rules configuration."""

    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_type: Mapped[str] = mapped_column(String(32), nullable=False)  # storage, queue_size, delivery_rate
    threshold_value: Mapped[float] = mapped_column(Float, nullable=False)
    threshold_operator: Mapped[str] = mapped_column(String(8), nullable=False)  # gt, lt, eq, gte, lte
    notification_type: Mapped[str] = mapped_column(String(32), nullable=False)  # email, webhook
    notification_target: Mapped[str] = mapped_column(Text, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    cooldown_minutes: Mapped[int] = mapped_column(Integer, default=60)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    history: Mapped[list["AlertHistory"]] = relationship(
        "AlertHistory", back_populates="rule", cascade="all, delete-orphan"
    )


class AlertHistory(Base):
    """Alert trigger history."""

    __tablename__ = "alert_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey("alert_rules.id"), nullable=False)
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    current_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    notification_sent: Mapped[bool] = mapped_column(Boolean, default=False)

    rule: Mapped["AlertRule"] = relationship("AlertRule", back_populates="history")


class AppSetting(Base):
    """Key-value store for application settings."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class StorageHistory(Base):
    """Storage usage history for trending."""

    __tablename__ = "storage_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    path: Mapped[str] = mapped_column(String(255), nullable=False)
    used_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)


class AuditLog(Base):
    """Audit log for admin actions."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("admin_users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


class LogAgentRun(Base):
    """One row per agent run, used for cost tracking and history."""

    __tablename__ = "log_agent_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lines_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    suggestions_created: Mapped[int] = mapped_column(Integer, default=0)
    model: Mapped[str] = mapped_column(String(64), default="")
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    suggestions: Mapped[list["BanSuggestion"]] = relationship(
        "BanSuggestion", back_populates="run", cascade="all, delete-orphan"
    )


class BanSuggestion(Base):
    """LLM-generated suggestion to ban an IP/CIDR or add it to the allowlist.

    Suggestions are advisory only — applying one calls the privileged helper
    via the existing approve route, which re-validates the target.
    """

    __tablename__ = "ban_suggestions"
    __table_args__ = (
        Index("ix_ban_suggestions_status_created", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    target: Mapped[str] = mapped_column(String(64), nullable=False)  # IP or CIDR
    action: Mapped[str] = mapped_column(String(16), nullable=False)  # "ban" | "allowlist"
    confidence: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    reason: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")  # JSON-serialized list of log lines
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    # "pending" | "approved" | "rejected" | "expired"
    reviewed_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("admin_users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    run_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("log_agent_runs.id", ondelete="SET NULL"), nullable=True
    )

    run: Mapped["LogAgentRun | None"] = relationship("LogAgentRun", back_populates="suggestions")


# Database engine and session
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
)

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session."""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables."""
    # Ensure data directory exists
    db_path = settings.database_url.replace("sqlite+aiosqlite:///", "")
    if db_path.startswith("./"):
        db_path = db_path[2:]
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def create_initial_admin(username: str, password: str, email: str | None = None) -> AdminUser:
    """Create an initial admin user if none exists."""
    from app.core.security import hash_password

    async with async_session() as session:
        # Check if any admin exists
        from sqlalchemy import select, func

        result = await session.execute(select(func.count(AdminUser.id)))
        count = result.scalar()

        if count > 0:
            raise ValueError("Admin user already exists")

        admin = AdminUser(
            username=username,
            password_hash=hash_password(password),
            email=email,
        )
        session.add(admin)
        await session.commit()
        await session.refresh(admin)
        return admin
