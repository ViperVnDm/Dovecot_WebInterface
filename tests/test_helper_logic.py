"""Unit tests for pure logic in the privileged helper and alert checker.

These tests do not require a running helper process, database, or HTTP server.
"""

import pytest
import sys
import os

# Make privileged/ importable without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── privileged/server.py ──────────────────────────────────────────────────────

from privileged.server import (
    validate_username,
    validate_queue_id,
    _validate_ip,
    _evaluate,
    CommandError,
)


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
        assert _validate_ip("255.255.255.255") == "255.255.255.255"

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


class TestEvaluate:
    def test_gt(self):
        assert _evaluate(90.0, "gt", 80.0) is True
        assert _evaluate(80.0, "gt", 80.0) is False
        assert _evaluate(70.0, "gt", 80.0) is False

    def test_gte(self):
        assert _evaluate(80.0, "gte", 80.0) is True
        assert _evaluate(81.0, "gte", 80.0) is True
        assert _evaluate(79.0, "gte", 80.0) is False

    def test_lt(self):
        assert _evaluate(70.0, "lt", 80.0) is True
        assert _evaluate(80.0, "lt", 80.0) is False

    def test_lte(self):
        assert _evaluate(80.0, "lte", 80.0) is True
        assert _evaluate(79.0, "lte", 80.0) is True
        assert _evaluate(81.0, "lte", 80.0) is False

    def test_eq(self):
        assert _evaluate(80.0, "eq", 80.0) is True
        assert _evaluate(80.1, "eq", 80.0) is False

    def test_unknown_operator(self):
        assert _evaluate(80.0, "unknown", 80.0) is False


# ── Log level detection (via cmd_read_logs internals) ─────────────────────────

import re

LOG_LEVEL_RE = re.compile(
    r"^(DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL)\b", re.IGNORECASE
)


def detect_level(message: str) -> str:
    """Reproduce the level-detection logic from cmd_read_logs."""
    prefix_match = LOG_LEVEL_RE.match(message)
    if prefix_match:
        prefix = prefix_match.group(1).upper()
        if prefix in ("ERROR", "CRITICAL", "FATAL"):
            return "error"
        if prefix in ("WARNING", "WARN"):
            return "warning"
        return "info"
    msg_lower = message.lower()
    if "error" in msg_lower or "fatal" in msg_lower:
        return "error"
    if "warning" in msg_lower or "warn" in msg_lower:
        return "warning"
    return "info"


class TestLogLevelDetection:
    def test_info_prefix(self):
        assert detect_level('INFO:     127.0.0.1 - "GET /dashboard HTTP/1.1" 200 OK') == "info"

    def test_warning_prefix(self):
        assert detect_level("WARNING: something went wrong") == "warning"

    def test_error_prefix(self):
        assert detect_level("ERROR: failed to connect") == "error"

    def test_url_with_level_param_not_false_positive(self):
        # e.g. uvicorn logging a request URL containing ?level=error
        msg = 'INFO:     127.0.0.1 - "GET /partials/logs/entries?level=error HTTP/1.1" 200 OK'
        assert detect_level(msg) == "info"

    def test_fastapi_deprecation_warning(self):
        msg = "FastAPIDeprecationWarning: `regex` has been deprecated, use `pattern` instead"
        assert detect_level(msg) == "warning"

    def test_auth_failed_syslog(self):
        msg = "authentication failed: user=<support>"
        assert detect_level(msg) == "error"

    def test_plain_info_syslog(self):
        msg = "connect from unknown[185.93.89.64]"
        assert detect_level(msg) == "info"


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
