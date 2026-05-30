"""Audit-log tests.

Verify that privileged actions write AuditLog rows (read back via the viewer
partial) and that the viewer is auth-protected.
"""

import pytest


@pytest.mark.asyncio
async def test_create_user_is_audited(auth_client):
    ac, _ = auth_client
    resp = await ac.post(
        "/api/users",
        data={"username": "alice", "password": "password123", "quota_mb": "0"},
    )
    assert resp.status_code == 200
    audit = await ac.get("/partials/audit/entries")
    assert audit.status_code == 200
    assert b"create_user" in audit.content
    assert b"alice" in audit.content


@pytest.mark.asyncio
async def test_delete_user_is_audited(auth_client):
    ac, _ = auth_client
    await ac.request("DELETE", "/api/users/bob")
    audit = await ac.get("/partials/audit/entries")
    assert b"delete_user" in audit.content
    assert b"bob" in audit.content


@pytest.mark.asyncio
async def test_ban_ip_is_audited(auth_client):
    ac, mock_helper = auth_client
    mock_helper.list_banned_ips.return_value = ["5.6.7.8"]
    resp = await ac.post("/api/logs/ban-ip", data={"ip": "5.6.7.8"})
    assert resp.status_code == 200
    audit = await ac.get("/partials/audit/entries")
    assert b"ban_ip" in audit.content
    assert b"5.6.7.8" in audit.content


@pytest.mark.asyncio
async def test_unban_ip_is_audited(auth_client):
    ac, _ = auth_client
    await ac.delete("/api/logs/ban-ip/9.9.9.9")
    audit = await ac.get("/partials/audit/entries")
    assert b"unban_ip" in audit.content


@pytest.mark.asyncio
async def test_create_alert_rule_is_audited(auth_client):
    ac, _ = auth_client
    resp = await ac.post(
        "/api/alerts/rules",
        data={
            "name": "Disk high", "rule_type": "storage",
            "threshold_operator": "gt", "threshold_value": "90",
            "notification_type": "email",
            "notification_target": "admin@example.com",
            "cooldown_minutes": "60",
        },
    )
    assert resp.status_code == 200
    audit = await ac.get("/partials/audit/entries")
    assert b"create_alert_rule" in audit.content


@pytest.mark.asyncio
async def test_audit_page_loads(auth_client):
    ac, _ = auth_client
    resp = await ac.get("/audit")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_audit_entries_requires_auth(client):
    ac, _ = client  # not logged in
    resp = await ac.get("/partials/audit/entries")
    assert resp.status_code == 401
