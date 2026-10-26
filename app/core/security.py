"""Authentication and security utilities."""

import asyncio
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db, AdminUser, Session, async_session

logger = logging.getLogger(__name__)
settings = get_settings()

# bcrypt only reads the first 72 bytes. passlib (which produced every hash
# already in the DB) truncated silently; bcrypt>=5 raises instead. Truncating
# here keeps long passwords that were set under passlib verifying.
_BCRYPT_MAX_BYTES = 72


def _bcrypt_input(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    return bcrypt.hashpw(_bcrypt_input(password), salt).decode("ascii")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(_bcrypt_input(plain_password), hashed_password.encode("ascii"))
    except ValueError:  # malformed hash
        return False


def generate_session_token() -> str:
    """Generate a secure random session token."""
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """Return the form of a session token that is stored in the DB.

    Only the SHA-256 digest is persisted, so a copy of admin.db (a backup, a
    read of the data dir) doesn't yield live session cookies. The token has
    256 bits of entropy, so an unsalted fast hash is sufficient.
    """
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def csrf_token_for_session(session_token: str) -> str:
    """CSRF token bound to a session: HMAC(SECRET_KEY, session token).

    A double-submit cookie that isn't bound to anything can be defeated by an
    attacker who can *write* a cookie for this host (e.g. from a sibling
    subdomain). Binding it to the HttpOnly session cookie means a planted
    CSRF cookie won't validate. See CSRFMiddleware.
    """
    return hmac.new(
        settings.secret_key.encode(), session_token.encode(), hashlib.sha256
    ).hexdigest()


async def create_session(
    db: AsyncSession,
    user_id: int,
    request: Request,
) -> str:
    """Create a new session for a user."""
    token = generate_session_token()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.session_expire_hours)

    session = Session(
        session_token=hash_session_token(token),
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
        .where(Session.session_token == hash_session_token(token))
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
    await db.execute(delete(Session).where(Session.session_token == hash_session_token(token)))
    await db.commit()


async def cleanup_expired_sessions(db: AsyncSession) -> int:
    """Remove expired sessions. Returns count of deleted sessions."""
    result = await db.execute(
        delete(Session).where(Session.expires_at <= datetime.now(timezone.utc))
    )
    await db.commit()
    return result.rowcount


async def cleanup_expired_sessions_loop(interval_seconds: int = 3600) -> None:
    """Background task: periodically purge expired sessions so the table does
    not grow without bound. Expired sessions are already rejected by
    validate_session; this just reclaims the rows."""
    logger.info("Session cleanup background task started")
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            async with async_session() as db:
                deleted = await cleanup_expired_sessions(db)
            if deleted:
                logger.info("Purged %d expired session(s)", deleted)
        except Exception:
            logger.exception("Session cleanup failed")


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AdminUser:
    """Dependency to get current authenticated user."""
    token = request.cookies.get(settings.session_cookie)
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

