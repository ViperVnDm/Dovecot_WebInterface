"""Shared test fixtures."""

import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

# Set required env BEFORE importing app modules
os.environ.setdefault("SECRET_KEY", "test-secret-key-with-enough-entropy-xx")
os.environ.setdefault("COOKIE_SECURE", "false")
# Effectively disable login rate limiting in tests (all requests come from
# 127.0.0.1 so the default 5/minute would otherwise quickly exhaust).
os.environ.setdefault("LOGIN_RATE_LIMIT", "10000/minute")

from app.database import Base, AdminUser, get_db
from app.core.security import hash_password
from app.config import get_settings

# Clear cached settings so test env vars take effect
get_settings.cache_clear()

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"
TEST_USERNAME = "testadmin"
TEST_PASSWORD = "testpassword123"


def make_mock_helper() -> AsyncMock:
    """Return a pre-configured mock of PrivilegedHelperClient."""
    mock = AsyncMock()
    mock.list_users.return_value = [
        {"username": "nick", "uid": 1002, "gid": 1006, "home": "/home/nick",
         "mailbox_size_bytes": 74448896, "mailbox_message_count": 312},
        {"username": "zucchini", "uid": 1003, "gid": 1007, "home": "/home/zucchini",
         "mailbox_size_bytes": 0, "mailbox_message_count": 0},
    ]
    mock.get_queue_stats.return_value = {
        "active": 0, "deferred": 0, "hold": 0, "incoming": 0, "total": 0,
    }
    mock.list_queue.return_value = []
    mock.read_logs.return_value = []
    mock.get_log_stats.return_value = {
        "sent_today": 0, "received_today": 0,
        "bounced_today": 0, "errors_today": 0,
    }
    mock.get_mailbox_sizes.return_value = [
        {"username": "nick", "size_bytes": 74448896, "message_count": 312},
    ]
    mock.list_banned_ips.return_value = []
    mock.ban_ip.return_value = {"success": True, "ip": "1.2.3.4"}
    mock.unban_ip.return_value = {"success": True, "ip": "1.2.3.4"}
    mock.read_auth_log.return_value = []
    mock.read_ufw_log.return_value = []
    return mock


@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine(TEST_DB_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


async def _prime_csrf(ac: AsyncClient) -> str:
    """Issue a GET to populate the CSRF cookie and return the token.

    Also installs the matching X-CSRF-Token header on the client so all
    subsequent unsafe requests pass middleware validation by default.
    """
    resp = await ac.get("/login", follow_redirects=False)
    token = resp.cookies.get("dwa_csrf")
    assert token, f"CSRF cookie not set by /login (status={resp.status_code})"
    # httpx doesn't always carry the cookie forward in ASGI mode; copy explicitly
    ac.cookies.set("dwa_csrf", token)
    ac.headers["X-CSRF-Token"] = token
    return token


@pytest_asyncio.fixture
async def client(db_engine):
    """Unauthenticated test client with in-memory DB and mocked helper."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_get_db():
        async with factory() as session:
            yield session

    # Seed admin user
    async with factory() as session:
        session.add(AdminUser(
            username=TEST_USERNAME,
            password_hash=hash_password(TEST_PASSWORD),
        ))
        await session.commit()

    mock_helper = make_mock_helper()

    from app.main import app
    app.dependency_overrides[get_db] = override_get_db

    async def _noop():
        return

    with patch("app.main.alert_checker_loop", side_effect=_noop), \
         patch("app.main.storage_collector_loop", side_effect=_noop), \
         patch("app.main.agent_loop", side_effect=_noop), \
         patch("app.core.permissions.get_helper_client", return_value=mock_helper), \
         patch("app.api.logs.get_helper_client", return_value=mock_helper), \
         patch("app.api.partials.get_helper_client", return_value=mock_helper), \
         patch("app.api.users.get_helper_client", return_value=mock_helper), \
         patch("app.api.agent.get_helper_client", return_value=mock_helper), \
         patch("app.services.log_agent.get_helper_client", return_value=mock_helper):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            await _prime_csrf(ac)
            yield ac, mock_helper

    app.dependency_overrides.clear()


def _csrf_headers(ac: AsyncClient) -> dict:
    """Build headers dict including the X-CSRF-Token from the client cookie jar."""
    token = ac.cookies.get("dwa_csrf", "")
    return {"X-CSRF-Token": token} if token else {}


@pytest_asyncio.fixture
async def auth_client(client):
    """Authenticated test client (session cookie already set)."""
    ac, mock_helper = client
    # /login is CSRF-exempt by design
    resp = await ac.post(
        "/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 302, f"Login failed: {resp.status_code} {resp.text}"
    return ac, mock_helper
