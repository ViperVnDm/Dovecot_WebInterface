"""Authentication tests."""

from urllib.parse import quote

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


PAGES = [
    "/dashboard", "/users", "/queue", "/logs", "/firewall",
    "/storage", "/alerts", "/agent", "/audit",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PAGES)
async def test_pages_redirect_to_login_when_unauthenticated(client, path):
    ac, _ = client
    resp = await ac.get(path, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == f"/login?next={quote(path, safe='')}"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PAGES)
async def test_htmx_page_requests_keep_the_401(client, path):
    """Boosted nav links (hx-boost on <body>) must NOT get the 302: XHR follows
    it invisibly and htmx would swap the login page in under the old URL. The
    401 is what reaches the htmx:responseError handler in base.html."""
    ac, _ = client
    resp = await ac.get(path, headers={"HX-Request": "true"}, follow_redirects=False)
    assert resp.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/auth/me", "/partials/audit/entries"])
async def test_api_and_partials_keep_the_401(client, path):
    """The redirect is for address-bar navigations only."""
    ac, _ = client
    resp = await ac.get(path, follow_redirects=False)
    assert resp.status_code == 401


# ── ?next= round-trip ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_redirect_preserves_path_and_query(client):
    ac, _ = client
    resp = await ac.get("/agent?sort=confidence", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?next=%2Fagent%3Fsort%3Dconfidence"


@pytest.mark.asyncio
async def test_login_returns_to_next(client):
    ac, _ = client
    resp = await ac.post(
        "/login",
        data={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
            "next": "/agent?sort=confidence",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/agent?sort=confidence"


@pytest.mark.asyncio
async def test_failed_login_keeps_next(client):
    """A typo on the way in must not lose the destination."""
    ac, _ = client
    resp = await ac.post(
        "/login",
        data={"username": TEST_USERNAME, "password": "wrong", "next": "/audit"},
        follow_redirects=False,
    )
    assert resp.status_code == 401
    assert b'name="next" value="/audit"' in resp.content


OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "/\\evil.com",
    "\\\\evil.com",
    "https://evil.com",
    "http://evil.com/path",
    "javascript:alert(1)",
    "/audit\nLocation: https://evil.com",
    "evil.com",
    "",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", OPEN_REDIRECT_PAYLOADS)
async def test_next_cannot_leave_the_site(client, payload):
    ac, _ = client
    resp = await ac.post(
        "/login",
        data={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
            "next": payload,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"


@pytest.mark.asyncio
async def test_next_cannot_bounce_back_to_login(client):
    """Otherwise a fresh session lands straight back on the login form."""
    ac, _ = client
    resp = await ac.post(
        "/login",
        data={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
            "next": "/login",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"


@pytest.mark.asyncio
async def test_login_page_rejects_hostile_next_in_the_form(client):
    """The hidden field is rendered from the sanitised value, not the raw query."""
    ac, _ = client
    resp = await ac.get("/login?next=//evil.com")
    assert resp.status_code == 200
    assert b"evil.com" not in resp.content
    assert b'name="next" value="/dashboard"' in resp.content


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
    # After logout, dashboard should bounce to login
    resp2 = await ac.get("/dashboard", follow_redirects=False)
    assert resp2.status_code == 302
    assert resp2.headers["location"] == "/login?next=%2Fdashboard"


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
