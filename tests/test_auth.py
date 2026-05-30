"""Authentication tests."""

import pytest
from tests.conftest import TEST_USERNAME, TEST_PASSWORD


@pytest.mark.asyncio
async def test_login_page_loads(client):
    ac, _ = client
    resp = await ac.get("/login")
    assert resp.status_code == 200
    assert b"login" in resp.content.lower()


@pytest.mark.asyncio
async def test_login_success_redirects_to_dashboard(client):
    ac, _ = client
    resp = await ac.post(
        "/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"
    assert "dwa_session" in resp.cookies


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401(client):
    ac, _ = client
    resp = await ac.post(
        "/login",
        data={"username": TEST_USERNAME, "password": "wrongpassword"},
        follow_redirects=False,
    )
    assert resp.status_code == 401
    assert b"Invalid username or password" in resp.content


@pytest.mark.asyncio
async def test_login_unknown_user_returns_401(client):
    ac, _ = client
    resp = await ac.post(
        "/login",
        data={"username": "nobody", "password": "whatever"},
        follow_redirects=False,
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_requires_auth(client):
    ac, _ = client
    resp = await ac.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_accessible_after_login(auth_client):
    ac, _ = auth_client
    resp = await ac.get("/dashboard")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_logout_clears_session(auth_client):
    ac, _ = auth_client
    resp = await ac.post("/logout", follow_redirects=False)
    assert resp.status_code == 302
    # After logout, dashboard should be inaccessible
    resp2 = await ac.get("/dashboard", follow_redirects=False)
    assert resp2.status_code == 401


@pytest.mark.asyncio
async def test_api_auth_me(auth_client):
    ac, _ = auth_client
    resp = await ac.get("/api/auth/me")
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == TEST_USERNAME


@pytest.mark.asyncio
async def test_api_auth_me_unauthenticated(client):
    ac, _ = client
    resp = await ac.get("/api/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_cleanup_expired_sessions(db_session):
    """cleanup_expired_sessions deletes only past-expiry rows."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from app.database import AdminUser, Session
    from app.core.security import cleanup_expired_sessions

    user = AdminUser(username="cleanup_user", password_hash="x")
    db_session.add(user)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    db_session.add(Session(
        session_token="expired-token", user_id=user.id,
        expires_at=now - timedelta(hours=1),
    ))
    db_session.add(Session(
        session_token="valid-token", user_id=user.id,
        expires_at=now + timedelta(hours=1),
    ))
    await db_session.commit()

    deleted = await cleanup_expired_sessions(db_session)
    assert deleted == 1

    remaining = (await db_session.execute(select(Session))).scalars().all()
    assert [s.session_token for s in remaining] == ["valid-token"]
