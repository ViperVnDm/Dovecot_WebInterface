"""Security hardening regression tests."""

from __future__ import annotations

import sys
import pytest
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport

from tests.conftest import TEST_USERNAME, TEST_PASSWORD


# Helper-side tests need privileged.server which uses Unix-only `grp`/`pwd`.
unix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="privileged helper tests require Unix (grp/pwd modules)",
)


# ── CSRF protection ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_csrf_required_on_unsafe_methods(auth_client):
    """POST without CSRF token must be rejected, even when authenticated."""
    ac, _ = auth_client
    # Send the request without the X-CSRF-Token header. We must also
    # remove the cookie (or send a mismatched header) to demonstrate
    # the protection — strip both to simulate a cross-origin attacker
    # who has no CSRF cookie value.
    # Override the CSRF cookie on the client jar to a value that won't
    # match the X-CSRF-Token header we send.
    ac.cookies.set("dwa_csrf", "different-value")
    resp = await ac.post(
        "/api/logs/allowlist",
        data={"entry": "1.2.3.4"},
        headers={"X-CSRF-Token": "wrong-token"},
    )
    assert resp.status_code == 403
    assert b"CSRF" in resp.content


@pytest.mark.asyncio
async def test_csrf_token_cookie_set_on_first_get(client):
    """A CSRF cookie should be issued on the first GET."""
    ac, _ = client
    # The conftest _prime_csrf already triggered a GET /login that set it.
    # httpx may track multiple cookies (different paths) — just confirm at
    # least one dwa_csrf cookie is present in the jar.
    csrf_cookies = [c for c in ac.cookies.jar if c.name == "dwa_csrf"]
    assert csrf_cookies, "CSRF cookie should be set"
    assert all(c.value for c in csrf_cookies)


@pytest.mark.asyncio
async def test_csrf_exempt_login(client):
    """Login is intentionally exempt from CSRF — protected by rate limit."""
    ac, _ = client
    # Send login without CSRF header - should still work
    headers = {k: v for k, v in ac.headers.items() if k.lower() != "x-csrf-token"}
    resp = await ac.post(
        "/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        headers=headers,
        follow_redirects=False,
    )
    assert resp.status_code == 302


# ── Security headers ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_security_headers_present(client):
    ac, _ = client
    resp = await ac.get("/login")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "Referrer-Policy" in resp.headers
    assert "Content-Security-Policy" in resp.headers
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]


# ── Login hardening ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_login_unknown_user_same_message_as_wrong_password(client):
    """Same error for unknown user as for wrong password (no enumeration)."""
    ac, _ = client
    r1 = await ac.post(
        "/login",
        data={"username": "nobody", "password": "wrong"},
        follow_redirects=False,
    )
    r2 = await ac.post(
        "/login",
        data={"username": TEST_USERNAME, "password": "wrong"},
        follow_redirects=False,
    )
    assert r1.status_code == r2.status_code == 401
    # Same error string in both responses
    assert b"Invalid username or password" in r1.content
    assert b"Invalid username or password" in r2.content


@pytest.mark.asyncio
async def test_session_cookie_name_changed(client):
    """The default session cookie name should no longer be the generic 'session'."""
    ac, _ = client
    resp = await ac.post(
        "/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "dwa_session" in resp.cookies
    assert "session" not in resp.cookies


@pytest.mark.asyncio
async def test_logout_clears_renamed_cookie(auth_client):
    ac, _ = auth_client
    assert ac.cookies.get("dwa_session"), "should be logged in"
    resp = await ac.post("/logout", follow_redirects=False)
    assert resp.status_code == 302
    # Subsequent dashboard hit should require auth
    resp2 = await ac.get("/dashboard", follow_redirects=False)
    assert resp2.status_code == 401


# ── Storage path traversal removed ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_storage_disk_ignores_path_param(auth_client):
    """The path query parameter must no longer be honoured."""
    ac, _ = auth_client
    resp = await ac.get("/api/storage/disk?path=/etc")
    assert resp.status_code == 200
    body = resp.json()
    # Path should be the configured mail spool path, not /etc
    assert body["path"] != "/etc"


# ── Alert rule validation ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alert_rule_rejects_bad_enum(auth_client):
    ac, _ = auth_client
    resp = await ac.post(
        "/api/alerts/rules",
        data={
            "name": "bad",
            "rule_type": "not_a_real_type",
            "threshold_operator": "gt",
            "threshold_value": 1,
            "notification_type": "email",
            "notification_target": "ops@example.com",
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_alert_rule_rejects_bad_operator(auth_client):
    ac, _ = auth_client
    resp = await ac.post(
        "/api/alerts/rules",
        data={
            "name": "bad",
            "rule_type": "storage",
            "threshold_operator": "BOGUS",
            "threshold_value": 1,
            "notification_type": "email",
            "notification_target": "ops@example.com",
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_alert_rule_rejects_email_with_newline(auth_client):
    ac, _ = auth_client
    resp = await ac.post(
        "/api/alerts/rules",
        data={
            "name": "x",
            "rule_type": "storage",
            "threshold_operator": "gt",
            "threshold_value": 1,
            "notification_type": "email",
            "notification_target": "ops@example.com\nBcc: attacker@evil.com",
        },
    )
    assert resp.status_code == 400


# ── SSRF / webhook URL validation ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_url_must_be_https(auth_client):
    ac, _ = auth_client
    resp = await ac.post(
        "/api/alerts/rules",
        data={
            "name": "x",
            "rule_type": "storage",
            "threshold_operator": "gt",
            "threshold_value": 1,
            "notification_type": "webhook",
            "notification_target": "http://example.com/hook",
        },
    )
    assert resp.status_code == 400
    assert b"HTTPS" in resp.content


@pytest.mark.asyncio
async def test_webhook_url_rejects_localhost(auth_client):
    ac, _ = auth_client
    # 127.x is loopback so getaddrinfo on the literal "127.0.0.1" returns it
    resp = await ac.post(
        "/api/alerts/rules",
        data={
            "name": "x",
            "rule_type": "storage",
            "threshold_operator": "gt",
            "threshold_value": 1,
            "notification_type": "webhook",
            "notification_target": "https://127.0.0.1/hook",
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_webhook_url_rejects_aws_metadata(auth_client):
    ac, _ = auth_client
    resp = await ac.post(
        "/api/alerts/rules",
        data={
            "name": "x",
            "rule_type": "storage",
            "threshold_operator": "gt",
            "threshold_value": 1,
            "notification_type": "webhook",
            "notification_target": "https://169.254.169.254/latest/meta-data/",
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_webhook_url_rejects_private_range(auth_client):
    ac, _ = auth_client
    resp = await ac.post(
        "/api/alerts/rules",
        data={
            "name": "x",
            "rule_type": "storage",
            "threshold_operator": "gt",
            "threshold_value": 1,
            "notification_type": "webhook",
            "notification_target": "https://10.0.0.5/hook",
        },
    )
    assert resp.status_code == 400


# ── Helper-side input validation ────────────────────────────────────────────


@unix_only
def test_password_validation_rejects_newline():
    """Defence against chpasswd injection via newlines."""
    from privileged.server import _validate_password, CommandError

    with pytest.raises(CommandError):
        _validate_password("mypass\nroot:hacked")


@unix_only
def test_password_validation_rejects_carriage_return():
    from privileged.server import _validate_password, CommandError

    with pytest.raises(CommandError):
        _validate_password("mypass\rmore")


@unix_only
def test_password_validation_rejects_colon():
    from privileged.server import _validate_password, CommandError

    with pytest.raises(CommandError):
        _validate_password("foo:bar:baz")


@unix_only
def test_password_validation_accepts_normal_password():
    from privileged.server import _validate_password

    assert _validate_password("normal-password-123") == "normal-password-123"


@unix_only
def test_password_validation_rejects_too_short():
    from privileged.server import _validate_password, CommandError

    with pytest.raises(CommandError):
        _validate_password("short")


@unix_only
def test_ip_validation_rejects_link_local():
    from privileged.server import _validate_ip, CommandError

    with pytest.raises(CommandError):
        _validate_ip("169.254.169.254")


@unix_only
def test_ip_validation_rejects_loopback():
    from privileged.server import _validate_ip, CommandError

    with pytest.raises(CommandError):
        _validate_ip("127.0.0.1")


@unix_only
def test_ip_validation_rejects_multicast():
    from privileged.server import _validate_ip, CommandError

    with pytest.raises(CommandError):
        _validate_ip("224.0.0.1")


@unix_only
def test_ip_validation_accepts_public_ip():
    from privileged.server import _validate_ip

    assert _validate_ip("198.51.100.42") == "198.51.100.42"


# ── Default secret key guard ────────────────────────────────────────────────


def test_settings_rejects_default_secret_in_production(monkeypatch):
    """Settings must refuse to load with the default placeholder unless DEBUG=true."""
    from app.config import Settings, DEFAULT_SECRET_KEY

    monkeypatch.setenv("SECRET_KEY", DEFAULT_SECRET_KEY)
    monkeypatch.setenv("DEBUG", "false")
    with pytest.raises(Exception) as exc:
        Settings()
    assert "SECRET_KEY" in str(exc.value)


def test_settings_accepts_default_secret_in_debug(monkeypatch):
    from app.config import Settings, DEFAULT_SECRET_KEY

    monkeypatch.setenv("SECRET_KEY", DEFAULT_SECRET_KEY)
    monkeypatch.setenv("DEBUG", "true")
    s = Settings()
    assert s.secret_key == DEFAULT_SECRET_KEY


def test_settings_rejects_short_secret(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("SECRET_KEY", "short")
    monkeypatch.setenv("DEBUG", "true")
    with pytest.raises(Exception):
        Settings()


# ── WebSocket auth ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_websocket_rejects_unauthenticated():
    """The WS endpoint must close immediately when no session cookie is present."""
    # Use the FastAPI TestClient because httpx ASGITransport doesn't speak WS.
    from fastapi.testclient import TestClient
    from app.main import app
    from starlette.websockets import WebSocketDisconnect

    with TestClient(app) as tc:
        with pytest.raises(WebSocketDisconnect) as ex:
            with tc.websocket_connect("/api/logs/ws") as ws:
                ws.receive_text()
        # Custom 4401 close code from our middleware
        assert ex.value.code == 4401


# ── Docs disabled in production ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_docs_disabled_in_production(client):
    """When DEBUG=false, /docs and /redoc must 404."""
    ac, _ = client
    # In tests DEBUG is unset (defaults to false)
    r1 = await ac.get("/docs")
    r2 = await ac.get("/openapi.json")
    assert r1.status_code == 404
    assert r2.status_code == 404

