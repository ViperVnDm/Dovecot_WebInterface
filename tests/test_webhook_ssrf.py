"""Webhook SSRF guards: address policy, redirect hops, and DNS pinning.

Everything here is offline — `socket.getaddrinfo` and the TLS connection are
both mocked, so no test opens a real socket.
"""

import socket
from unittest.mock import MagicMock, patch

import pytest

from app.core import webhook
from app.core.webhook import (
    WebhookTargetError,
    deliver_webhook,
    validate_webhook_url,
)

PUBLIC_IP = "93.184.216.34"


def _addrinfo(*ips):
    """Build a getaddrinfo-shaped return value for the given addresses."""
    out = []
    for ip in ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sockaddr = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
        out.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
    return out


def _resolves_to(*ips):
    return patch.object(socket, "getaddrinfo", return_value=_addrinfo(*ips))


class _FakeResponse:
    def __init__(self, status, location=None):
        self.status = status
        self._location = location

    def getheader(self, name):
        return self._location if name.lower() == "location" else None

    def read(self):
        return b"sensitive internal response body"


class _FakeConn:
    """Stands in for an HTTPSConnection, recording what was sent."""

    def __init__(self, responses):
        self._responses = responses
        self.requests = []

    def request(self, method, target, body=None, headers=None):
        self.requests.append((method, target, body))

    def getresponse(self):
        return self._responses.pop(0)

    def close(self):
        pass


# ── Address policy ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",       # loopback
        "10.0.0.5",        # private
        "192.168.1.1",     # private
        "172.16.0.1",      # private
        "169.254.169.254",  # link-local / cloud metadata
        "0.0.0.0",         # unspecified
        "224.0.0.1",       # multicast
        "::1",             # v6 loopback
        "fc00::1",         # v6 unique-local
        "::ffff:127.0.0.1",  # v4-mapped loopback — .is_loopback is False on v6
        "::ffff:10.0.0.1",   # v4-mapped private
    ],
)
def test_forbidden_addresses_are_rejected(ip):
    with _resolves_to(ip):
        with pytest.raises(WebhookTargetError):
            validate_webhook_url("https://hook.example.com/x")


def test_public_address_is_accepted():
    with _resolves_to(PUBLIC_IP):
        assert validate_webhook_url("https://hook.example.com/x") == "https://hook.example.com/x"


def test_mixed_answer_is_rejected():
    """A name answering with one public and one private address must not pass
    on a lucky ordering."""
    with _resolves_to(PUBLIC_IP, "10.0.0.5"):
        with pytest.raises(WebhookTargetError):
            validate_webhook_url("https://hook.example.com/x")


@pytest.mark.parametrize(
    "url",
    ["http://hook.example.com/x", "ftp://hook.example.com/x", "file:///etc/passwd", ""],
)
def test_non_https_rejected(url):
    with _resolves_to(PUBLIC_IP):
        with pytest.raises(WebhookTargetError):
            validate_webhook_url(url)


def test_unresolvable_host_rejected():
    with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror):
        with pytest.raises(WebhookTargetError):
            validate_webhook_url("https://nope.example.com/x")


# ── Delivery: redirects ──────────────────────────────────────────────────────


def test_redirect_to_internal_host_is_blocked():
    """The original bug: urlopen would follow this 302 to the metadata service."""
    conn = _FakeConn([_FakeResponse(302, "http://169.254.169.254/latest/meta-data/")])
    with _resolves_to(PUBLIC_IP), patch.object(webhook, "_open_connection", return_value=conn):
        with pytest.raises(WebhookTargetError):
            deliver_webhook("https://hook.example.com/x", b"{}")
    # Only the first (legitimate) request went out.
    assert len(conn.requests) == 1


def test_redirect_downgrade_to_http_is_blocked():
    conn = _FakeConn([_FakeResponse(302, "http://hook.example.com/x")])
    with _resolves_to(PUBLIC_IP), patch.object(webhook, "_open_connection", return_value=conn):
        with pytest.raises(WebhookTargetError):
            deliver_webhook("https://hook.example.com/x", b"{}")


def test_redirect_to_private_host_is_blocked_even_over_https():
    calls = []

    def fake_getaddrinfo(host, port, **kwargs):
        calls.append(host)
        return _addrinfo(PUBLIC_IP if host == "hook.example.com" else "10.0.0.5")

    conn = _FakeConn([_FakeResponse(302, "https://internal.example.com/admin")])
    with patch.object(socket, "getaddrinfo", side_effect=fake_getaddrinfo), \
            patch.object(webhook, "_open_connection", return_value=conn):
        with pytest.raises(WebhookTargetError):
            deliver_webhook("https://hook.example.com/x", b"{}")
    assert calls == ["hook.example.com", "internal.example.com"]


def test_redirect_to_public_https_is_followed_without_body():
    conn = _FakeConn([
        _FakeResponse(302, "https://hook.example.com/moved"),
        _FakeResponse(200),
    ])
    with _resolves_to(PUBLIC_IP), patch.object(webhook, "_open_connection", return_value=conn):
        deliver_webhook("https://hook.example.com/x", b'{"a":1}')
    assert conn.requests[0] == ("POST", "/x", b'{"a":1}')
    # 302 drops to a bodyless GET, matching browser and urllib behaviour.
    assert conn.requests[1] == ("GET", "/moved", None)


def test_307_preserves_method_and_body():
    conn = _FakeConn([
        _FakeResponse(307, "https://hook.example.com/moved"),
        _FakeResponse(200),
    ])
    with _resolves_to(PUBLIC_IP), patch.object(webhook, "_open_connection", return_value=conn):
        deliver_webhook("https://hook.example.com/x", b'{"a":1}')
    assert conn.requests[1] == ("POST", "/moved", b'{"a":1}')


def test_redirect_loop_is_bounded():
    conn = _FakeConn([_FakeResponse(302, "https://hook.example.com/x")] * 10)
    with _resolves_to(PUBLIC_IP), patch.object(webhook, "_open_connection", return_value=conn):
        with pytest.raises(WebhookTargetError, match="Too many"):
            deliver_webhook("https://hook.example.com/x", b"{}")
    assert len(conn.requests) == webhook.MAX_REDIRECTS + 1


# ── Delivery: DNS pinning ────────────────────────────────────────────────────


def test_connection_dials_the_validated_address():
    """The address we checked is the address we connect to — no second lookup
    for a rebinding attacker to answer differently."""
    conn = _FakeConn([_FakeResponse(200)])
    opener = MagicMock(return_value=conn)
    with _resolves_to(PUBLIC_IP), patch.object(webhook, "_open_connection", opener):
        deliver_webhook("https://hook.example.com/x", b"{}")
    opener.assert_called_once_with("hook.example.com", 443, PUBLIC_IP)


def test_open_connection_pins_ip_and_keeps_hostname_for_tls():
    """Guards the two properties that make pinning safe: connect by IP, but
    verify the certificate against the hostname."""
    with patch.object(socket, "create_connection") as create_conn, \
            patch.object(webhook.ssl, "create_default_context") as make_ctx:
        webhook._open_connection("hook.example.com", 443, PUBLIC_IP)

    create_conn.assert_called_once()
    assert create_conn.call_args[0][0] == (PUBLIC_IP, 443)
    ctx = make_ctx.return_value
    assert ctx.wrap_socket.call_args.kwargs["server_hostname"] == "hook.example.com"
    # create_default_context() verifies certs and hostnames. Pinning must not
    # pay for itself by weakening that — assigning either attribute would show
    # up in the mock's __dict__.
    assert make_ctx.called, "must build the verifying default context"
    for attr in ("check_hostname", "verify_mode"):
        assert attr not in ctx.__dict__, f"_open_connection must not weaken {attr}"


def test_default_context_is_the_verifying_one():
    """Pins the property the test above relies on: the context builder we use
    verifies, unlike smtplib's ssl._create_stdlib_context()."""
    ctx = webhook.ssl.create_default_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode is webhook.ssl.CERT_REQUIRED


# ── Delivery: response handling ──────────────────────────────────────────────


def test_error_status_raises():
    conn = _FakeConn([_FakeResponse(500)])
    with _resolves_to(PUBLIC_IP), patch.object(webhook, "_open_connection", return_value=conn):
        with pytest.raises(WebhookTargetError, match="HTTP 500"):
            deliver_webhook("https://hook.example.com/x", b"{}")


def test_response_body_is_never_returned():
    """Delivery stays blind: nothing from the endpoint reaches the caller."""
    conn = _FakeConn([_FakeResponse(200)])
    with _resolves_to(PUBLIC_IP), patch.object(webhook, "_open_connection", return_value=conn):
        assert deliver_webhook("https://hook.example.com/x", b"{}") is None


# ── Wiring: the alert path actually uses the guarded delivery ────────────────


def test_send_webhook_uses_guarded_delivery():
    from app.services import alert_checker

    rule = MagicMock()
    rule.name = "disk"
    rule.rule_type = "storage"
    rule.threshold_operator = "gt"
    rule.threshold_value = 90.0
    rule.notification_target = "https://hook.example.com/x"

    with patch.object(alert_checker, "deliver_webhook") as delivery:
        assert alert_checker._send_webhook(rule, 95.0, "disk full") is True
    delivery.assert_called_once()
    assert delivery.call_args[0][0] == "https://hook.example.com/x"


def test_send_webhook_returns_false_when_blocked():
    from app.services import alert_checker

    rule = MagicMock()
    rule.name = "disk"
    rule.rule_type = "storage"
    rule.threshold_operator = "gt"
    rule.threshold_value = 90.0
    rule.notification_target = "https://hook.example.com/x"

    with patch.object(
        alert_checker, "deliver_webhook", side_effect=WebhookTargetError("blocked")
    ):
        assert alert_checker._send_webhook(rule, 95.0, "disk full") is False
