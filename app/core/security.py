"""Authentication and security utilities."""

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from passlib.context import CryptContext
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db, AdminUser, Session

settings = get_settings()

# Password hashing
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.bcrypt_rounds,
)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def generate_session_token() -> str:
    """Generate a secure random session token."""
    return secrets.token_urlsafe(32)


async def create_session(
    db: AsyncSession,
    user_id: int,
    request: Request,
) -> str:
    """Create a new session for a user."""
    token = generate_session_token()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.session_expire_hours)

    session = Session(
        session_token=token,
        user_id=user_id,
        expires_at=expires_at,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.add(session)
    await db.commit()

    # Update last login
    result = await db.execute(select(AdminUser).where(AdminUser.id == user_id))
    user = result.scalar_one()
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    return token


async def validate_session(db: AsyncSession, token: str) -> AdminUser | None:
    """Validate a session token and return the associated user."""
    result = await db.execute(
        select(Session)
        .where(Session.session_token == token)
        .where(Session.expires_at > datetime.now(timezone.utc))
    )
    session = result.scalar_one_or_none()

    if not session:
        return None

    # Get user
    result = await db.execute(
        select(AdminUser)
        .where(AdminUser.id == session.user_id)
        .where(AdminUser.is_active == True)
    )
    return result.scalar_one_or_none()


async def delete_session(db: AsyncSession, token: str) -> None:
    """Delete a session."""
    await db.execute(delete(Session).where(Session.session_token == token))
    await db.commit()


async def cleanup_expired_sessions(db: AsyncSession) -> int:
    """Remove expired sessions. Returns count of deleted sessions."""
    result = await db.execute(
        delete(Session).where(Session.expires_at <= datetime.now(timezone.utc))
    )
    await db.commit()
    return result.rowcount


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AdminUser:
    """Dependency to get current authenticated user."""
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await validate_session(db, token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def generate_csrf_token() -> str:
    """Generate a CSRF token."""
    return secrets.token_urlsafe(32)
