"""Unit tests for pure logic in the privileged helper and alert checker.

These tests do not require a running helper process, database, or HTTP server.
"""

import pytest
import sys
import os

# Make privileged/ importable without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# privileged/server.py uses grp/pwd which are Unix-only
if sys.platform == "win32":
    pytest.skip("privileged helper tests require Unix", allow_module_level=True)


# ── privileged/server.py ──────────────────────────────────────────────────────

from privileged.server import (
    validate_username,
    validate_queue_id,
    _validate_ip,
    _validate_ip_or_cidr,
    _require_mail_user,
    CommandError,
)
from privileged import server


class TestValidateUsername:
    def test_valid(self):
        assert validate_username("nick") == "nick"
        assert validate_username("test-user") == "test-user"
        assert validate_username("abc123") == "abc123"

    def test_too_short(self):
        with pytest.raises(CommandError):
            validate_username("ab")

    def test_starts_with_number(self):
        with pytest.raises(CommandError):
            validate_username("1nick")

    def test_uppercase(self):
        with pytest.raises(CommandError):
            validate_username("Nick")

    def test_reserved(self):
        with pytest.raises(CommandError):
            validate_username("root")
        with pytest.raises(CommandError):
            validate_username("postfix")

    def test_empty(self):
        with pytest.raises(CommandError):
            validate_username("")


class TestValidateQueueId:
    def test_valid(self):
        assert validate_queue_id("ABCDEF123456") == "ABCDEF123456"
        assert validate_queue_id("1234567890AB") == "1234567890AB"

    def test_too_short(self):
        with pytest.raises(CommandError):
            validate_queue_id("ABC")

    def test_lowercase(self):
        with pytest.raises(CommandError):
            validate_queue_id("abcdef123456")

    def test_empty(self):
        with pytest.raises(CommandError):
            validate_queue_id("")


class TestValidateIp:
    def test_valid(self):
        assert _validate_ip("1.2.3.4") == "1.2.3.4"
        assert _validate_ip("8.8.8.8") == "8.8.8.8"

    def test_reserved_or_broadcast_rejected(self):
        # 255.255.255.255 (limited broadcast) and 240.0.0.0/4 (Class E) are
        # reserved — nonsensical to ban, and _validate_ip now rejects them.
        with pytest.raises(CommandError):
            _validate_ip("255.255.255.255")
        with pytest.raises(CommandError):
            _validate_ip("240.0.0.1")

    def test_loopback_rejected(self):
        with pytest.raises(CommandError):
            _validate_ip("127.0.0.1")

    def test_wildcard_rejected(self):
        with pytest.raises(CommandError):
            _validate_ip("0.0.0.0")

    def test_invalid_format(self):
        with pytest.raises(CommandError):
            _validate_ip("not-an-ip")
        with pytest.raises(CommandError):
            _validate_ip("1.2.3")

    def test_octet_out_of_range(self):
        with pytest.raises(CommandError):
            _validate_ip("256.0.0.1")

    def test_strips_whitespace(self):
        assert _validate_ip(" 1.2.3.4 ") == "1.2.3.4"


class TestValidateIpOrCidr:
    def test_narrow_cidr_ok(self):
        assert _validate_ip_or_cidr("45.33.0.0/16") == "45.33.0.0/16"
        assert _validate_ip_or_cidr("45.33.12.0/24") == "45.33.12.0/24"

    def test_broad_cidr_rejected(self):
        # /0 from a non-zero base address used to pass and block everything.
        for value in ("1.0.0.0/0", "8.0.0.0/1", "45.32.0.0/15"):
            with pytest.raises(CommandError):
                _validate_ip_or_cidr(value)

    def test_special_ranges_rejected(self):
        for value in ("127.0.0.0/16", "0.0.0.0/16", "169.254.0.0/16", "224.0.0.0/24"):
            with pytest.raises(CommandError):
                _validate_ip_or_cidr(value)

    def test_unban_skips_breadth_policy(self):
        # A rule that predates the policy must still be removable.
        assert _validate_ip_or_cidr("8.0.0.0/8", for_ban=False) == "8.0.0.0/8"

    def test_bad_format_rejected_even_for_unban(self):
        for value in ("1.2.3.4/33", "300.0.0.0/16", "1.2.3.4/16; rm"):
            with pytest.raises(CommandError):
                _validate_ip_or_cidr(value, for_ban=False)


class TestRequireMailUser:
    """set_password / delete_user / set_quota may only touch mail-only accounts."""

    @pytest.fixture(autouse=True)
    def _fake_accounts(self, monkeypatch):
        import grp
        import pwd

        def entry(name, uid, gid, shell):
            return pwd.struct_passwd((name, "x", uid, gid, "", f"/home/{name}", shell))

        accounts = {
            "alice": entry("alice", 1001, 1001, "/usr/sbin/nologin"),
            "ubuntu": entry("ubuntu", 1000, 1000, "/bin/bash"),
            "svc": entry("svc", 999, 999, "/usr/sbin/nologin"),
            "outsider": entry("outsider", 1002, 1002, "/usr/sbin/nologin"),
        }

        def getpwnam(name):
            return accounts[name]

        monkeypatch.setattr(server.pwd, "getpwnam", getpwnam)
        monkeypatch.setattr(
            server.grp, "getgrnam",
            lambda name: grp.struct_group(("mail", "x", 8, ["alice", "ubuntu", "svc"])),
        )

    def test_mail_account_allowed(self):
        assert _require_mail_user("alice").pw_name == "alice"

    def test_login_shell_refused(self):
        with pytest.raises(CommandError) as exc:
            _require_mail_user("ubuntu")
        assert exc.value.code == 403

    def test_system_uid_refused(self):
        with pytest.raises(CommandError):
            _require_mail_user("svc")

    def test_not_in_mail_group_refused(self):
        with pytest.raises(CommandError):
            _require_mail_user("outsider")

    def test_missing_user_is_404(self):
        with pytest.raises(CommandError) as exc:
            _require_mail_user("ghost")
        assert exc.value.code == 404

    def test_set_password_refuses_login_account(self, monkeypatch):
        ran = []
        monkeypatch.setattr(server, "run_command", lambda *a, **k: ran.append(a))
        with pytest.raises(CommandError):
            server.cmd_set_password({"username": "ubuntu", "password": "longenough"})
        assert ran == []


# ── Log level detection (imported from the helper — no duplicated copy) ───────

from privileged.server import detect_log_level


class TestLogLevelDetection:
    def test_info_prefix(self):
        assert detect_log_level('INFO:     127.0.0.1 - "GET /dashboard HTTP/1.1" 200 OK') == "info"

    def test_warning_prefix(self):
        assert detect_log_level("WARNING: something went wrong") == "warning"

    def test_error_prefix(self):
        assert detect_log_level("ERROR: failed to connect") == "error"

    def test_url_with_level_param_not_false_positive(self):
        # e.g. uvicorn logging a request URL containing ?level=error
        msg = 'INFO:     127.0.0.1 - "GET /partials/logs/entries?level=error HTTP/1.1" 200 OK'
        assert detect_log_level(msg) == "info"

    def test_fastapi_deprecation_warning(self):
        msg = "FastAPIDeprecationWarning: `regex` has been deprecated, use `pattern` instead"
        assert detect_log_level(msg) == "warning"

    def test_auth_failed_syslog(self):
        # Step E16 decision: auth-failure lines surface as "warning" — security-
        # relevant, but not "error" (failed logins are routine bot traffic).
        msg = "authentication failed: user=<support>"
        assert detect_log_level(msg) == "warning"

    def test_plain_info_syslog(self):
        msg = "connect from unknown[185.93.89.64]"
        assert detect_log_level(msg) == "info"


# ── Alert checker _evaluate (same logic, exported separately) ─────────────────

from app.services.alert_checker import _evaluate as checker_evaluate


class TestCheckerEvaluate:
    """Ensure alert_checker._evaluate is consistent with helper._evaluate."""

    def test_gt_true(self):
        assert checker_evaluate(95.0, "gt", 90.0) is True

    def test_gt_false(self):
        assert checker_evaluate(85.0, "gt", 90.0) is False

    def test_gte_boundary(self):
        assert checker_evaluate(90.0, "gte", 90.0) is True

    def test_lt_true(self):
        assert checker_evaluate(5, "lt", 10) is True

    def test_unknown_operator(self):
        assert checker_evaluate(100, "??", 50) is False


# ── handle_client dispatch (commands run in a thread executor) ────────────────

import asyncio
import json
import threading


class _FakeWriter:
    """Minimal asyncio StreamWriter stand-in for handle_client tests."""

    def __init__(self):
        self.buf = bytearray()

    def get_extra_info(self, name):
        return None  # no peername/socket → the SO_PEERCRED check is skipped

    def write(self, data):
        self.buf += data

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


@pytest.mark.asyncio
async def test_handle_client_runs_command_in_worker_thread(monkeypatch):
    """Dispatch returns the command result AND runs it off the event loop."""
    from privileged import server

    main_thread = threading.get_ident()
    ran_on = {}

    def fake_cmd(params):
        ran_on["thread"] = threading.get_ident()
        return {"ok": True, "echo": params.get("x")}

    monkeypatch.setitem(server.COMMANDS, "fake_cmd", fake_cmd)

    reader = asyncio.StreamReader()
    reader.feed_data(
        json.dumps({"command": "fake_cmd", "params": {"x": 42}}).encode() + b"\n"
    )
    reader.feed_eof()
    writer = _FakeWriter()

    await server.handle_client(reader, writer)

    resp = json.loads(bytes(writer.buf).decode().strip())
    assert resp == {"ok": True, "echo": 42}
    # Proves the blocking command ran in a worker thread, not the event loop.
    assert ran_on["thread"] != main_thread


# ── Log-stats caching ─────────────────────────────────────────────────────────


def test_log_stats_cached_within_ttl(monkeypatch):
    """A second call inside the TTL is served from cache (no rescan)."""
    from privileged import server

    calls = {"n": 0}

    def fake_compute(today):
        calls["n"] += 1
        return {"sent_today": 1, "received_today": 0, "bounced_today": 0, "errors_today": 0}

    monkeypatch.setattr(server, "_compute_log_stats", fake_compute)
    # Start from a clean cache so the test is order-independent.
    server._log_stats_cache.update(date=None, ts=0.0, value=None)

    first = server.cmd_get_log_stats({})
    second = server.cmd_get_log_stats({})

    assert first == second == {
        "sent_today": 1, "received_today": 0, "bounced_today": 0, "errors_today": 0,
    }
    assert calls["n"] == 1  # second call hit the cache
