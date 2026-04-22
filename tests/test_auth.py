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
