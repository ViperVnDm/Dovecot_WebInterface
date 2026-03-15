"""Log allowlist and IP ban tests."""

import pytest
from app.api.logs import is_allowlisted, _parse_allowlist


# ── Pure unit tests (no HTTP) ─────────────────────────────────────────────────

class TestParseAllowlist:
    def test_empty_string(self):
        assert _parse_allowlist("") == []

    def test_single_ip(self):
        assert _parse_allowlist("1.2.3.4") == ["1.2.3.4"]

    def test_multiple_ips(self):
        result = _parse_allowlist("1.2.3.4,5.6.7.8")
        assert result == ["1.2.3.4", "5.6.7.8"]

    def test_cidr(self):
        assert _parse_allowlist("192.168.1.0/24") == ["192.168.1.0/24"]

    def test_strips_whitespace(self):
        assert _parse_allowlist(" 1.2.3.4 , 5.6.7.8 ") == ["1.2.3.4", "5.6.7.8"]

    def test_ignores_empty_segments(self):
        assert _parse_allowlist("1.2.3.4,,5.6.7.8") == ["1.2.3.4", "5.6.7.8"]


class TestIsAllowlisted:
    def test_exact_match(self):
        assert is_allowlisted("1.2.3.4", ["1.2.3.4"])

    def test_no_match(self):
        assert not is_allowlisted("1.2.3.5", ["1.2.3.4"])

    def test_cidr_match(self):
        assert is_allowlisted("192.168.1.50", ["192.168.1.0/24"])

    def test_cidr_no_match(self):
        assert not is_allowlisted("192.168.2.1", ["192.168.1.0/24"])

    def test_empty_allowlist(self):
        assert not is_allowlisted("1.2.3.4", [])

    def test_invalid_ip_returns_false(self):
        assert not is_allowlisted("not-an-ip", ["1.2.3.4"])

    def test_server_ip_in_allowlist(self):
        # Simulates the server's own public IP being protected
        assert is_allowlisted("199.19.75.246", ["199.19.75.246"])

    def test_home_network_cidr(self):
        assert is_allowlisted("10.0.0.100", ["10.0.0.0/8"])
        assert not is_allowlisted("172.16.0.1", ["10.0.0.0/8"])


# ── HTTP integration tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_allowlist_empty_initially(auth_client):
    ac, _ = auth_client
    resp = await ac.get("/partials/logs/allowlist")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_add_ip_to_allowlist(auth_client):
    ac, _ = auth_client
    resp = await ac.post("/api/logs/allowlist", data={"entry": "199.19.75.246"})
    assert resp.status_code == 200
    assert b"199.19.75.246" in resp.content


@pytest.mark.asyncio
async def test_add_cidr_to_allowlist(auth_client):
    ac, _ = auth_client
    resp = await ac.post("/api/logs/allowlist", data={"entry": "10.0.0.0/8"})
    assert resp.status_code == 200
    assert b"10.0.0.0/8" in resp.content


@pytest.mark.asyncio
async def test_add_invalid_entry_returns_400(auth_client):
    ac, _ = auth_client
    resp = await ac.post("/api/logs/allowlist", data={"entry": "not-an-ip"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_remove_from_allowlist(auth_client):
    ac, _ = auth_client
    await ac.post("/api/logs/allowlist", data={"entry": "1.2.3.4"})
    resp = await ac.delete("/api/logs/allowlist/1.2.3.4")
    assert resp.status_code == 200
    assert b"1.2.3.4" not in resp.content


@pytest.mark.asyncio
async def test_duplicate_allowlist_entry_not_added_twice(auth_client):
    ac, _ = auth_client
    await ac.post("/api/logs/allowlist", data={"entry": "1.2.3.4"})
    await ac.post("/api/logs/allowlist", data={"entry": "1.2.3.4"})
    resp = await ac.get("/partials/logs/allowlist")
    # Each entry renders one <span> with the IP — count spans to detect duplicates
    assert resp.text.count(">1.2.3.4<") == 1


@pytest.mark.asyncio
async def test_ban_ip(auth_client):
    ac, mock_helper = auth_client
    resp = await ac.post("/api/logs/ban-ip", data={"ip": "5.6.7.8"})
    assert resp.status_code == 200
    mock_helper.ban_ip.assert_called_once_with("5.6.7.8")


@pytest.mark.asyncio
async def test_ban_allowlisted_ip_rejected(auth_client):
    ac, mock_helper = auth_client
    # Add IP to allowlist first
    await ac.post("/api/logs/allowlist", data={"entry": "199.19.75.246"})
    # Try to ban it
    resp = await ac.post("/api/logs/ban-ip", data={"ip": "199.19.75.246"})
    assert resp.status_code == 403
    mock_helper.ban_ip.assert_not_called()


@pytest.mark.asyncio
async def test_unban_ip(auth_client):
    ac, mock_helper = auth_client
    resp = await ac.delete("/api/logs/ban-ip/5.6.7.8")
    assert resp.status_code == 200
    mock_helper.unban_ip.assert_called_once_with("5.6.7.8")


@pytest.mark.asyncio
async def test_logs_entries_partial(auth_client):
    ac, _ = auth_client
    resp = await ac.get("/partials/logs/entries")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_logs_stats_partial(auth_client):
    ac, _ = auth_client
    resp = await ac.get("/partials/logs/stats")
    assert resp.status_code == 200
    assert b"Sent Today" in resp.content


@pytest.mark.asyncio
async def test_logs_banned_partial(auth_client):
    ac, _ = auth_client
    resp = await ac.get("/partials/logs/banned")
    assert resp.status_code == 200
