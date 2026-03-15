"""Shared test fixtures."""

import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.database import Base, AdminUser, get_db
from app.core.security import hash_password
from app.config import get_settings

# Clear cached settings so COOKIE_SECURE=false takes effect
get_settings.cache_clear()

# Disable secure-only cookies so the test HTTP client (plain HTTP) can send them.
os.environ["COOKIE_SECURE"] = "false"

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
         patch("app.core.permissions.get_helper_client", return_value=mock_helper), \
         patch("app.api.logs.get_helper_client", return_value=mock_helper), \
         patch("app.api.partials.get_helper_client", return_value=mock_helper), \
         patch("app.api.users.get_helper_client", return_value=mock_helper):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac, mock_helper

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def auth_client(client):
    """Authenticated test client (session cookie already set)."""
    ac, mock_helper = client
    resp = await ac.post(
        "/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 302, f"Login failed: {resp.status_code} {resp.text}"
    return ac, mock_helper
