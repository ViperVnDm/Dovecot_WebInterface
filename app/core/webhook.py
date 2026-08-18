"""Outbound webhook delivery, with SSRF guards on every hop.

Alert webhooks are the only place the app makes an outbound request to an
operator-supplied URL, so this module owns the whole path: the address policy
used when a rule is saved *and* the delivery used when it fires.

Three things this defends against, all of which the previous
`urllib.request.urlopen()` call was open to:

- **Redirects.** urlopen follows them silently, so an https public host could
  302 to `http://169.254.169.254/` or any internal service. Every hop is
  re-validated here, and redirects may only go to https.
- **DNS rebinding.** Validating at rule-creation time and resolving again at
  send time are two different answers. We resolve once, check that answer, and
  connect to *that address* — `server_hostname` keeps SNI and certificate
  verification pointed at the real hostname, so pinning costs no TLS strength.
- **IPv4-mapped IPv6.** `ipaddress.ip_address("::ffff:127.0.0.1").is_loopback`
  is False; the mapped form is unwrapped before the policy check.

Delivery is deliberately blind — the response body is drained and discarded,
never logged or surfaced — so this cannot be used to read an internal
endpoint even if some future change lets a request through.
"""

import http.client
import ipaddress
import logging
import socket
import ssl
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# A webhook provider that needs more than a couple of hops is misconfigured.
MAX_REDIRECTS = 3
TIMEOUT_SECONDS = 10
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
# 301/302/303 drop to a bodyless GET (what browsers and urllib do); 307/308
# preserve method and body, which is what RFC 7231 requires.
_REDIRECT_DROPS_BODY = frozenset({301, 302, 303})


class WebhookTargetError(ValueError):
    """The URL is not an acceptable webhook target."""


def _forbidden_reason(ip: ipaddress._BaseAddress) -> str | None:
    """Return why this address is off-limits, or None if it is acceptable."""
    # ::ffff:10.0.0.1 is a private address wearing a v6 costume.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    for attr in (
        "is_private",
        "is_loopback",
        "is_link_local",
        "is_multicast",
        "is_reserved",
        "is_unspecified",
    ):
        if getattr(ip, attr, False):
            return attr
    return None


def _resolve_and_check(hostname: str, port: int) -> str:
    """Resolve `hostname` and return the single address we will dial.

    Rejects the host if *any* returned address is off-limits, so a name that
    answers with one public and one private address cannot slip through on a
    lucky ordering.
    """
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise WebhookTargetError(f"Cannot resolve webhook hostname: {hostname}")

    pinned: str | None = None
    for *_unused, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _forbidden_reason(ip) is not None:
            raise WebhookTargetError(
                f"Webhook URL resolves to a forbidden address ({ip_str}). "
                "Webhooks may not target private, loopback, or link-local hosts."
            )
        if pinned is None:
            pinned = ip_str

    if pinned is None:
        raise WebhookTargetError(f"Cannot resolve webhook hostname: {hostname}")
    return pinned


def _prepare(url: str) -> tuple[str, int, str, str]:
    """Validate one URL. Returns (hostname, port, request_target, pinned_ip)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise WebhookTargetError("Webhook URL must use HTTPS")
    if not parsed.hostname:
        raise WebhookTargetError("Webhook URL must include a hostname")
    try:
        port = parsed.port or 443
    except ValueError:
        raise WebhookTargetError("Webhook URL has an invalid port")

    pinned_ip = _resolve_and_check(parsed.hostname, port)

    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return parsed.hostname, port, target, pinned_ip


def validate_webhook_url(url: str) -> str:
    """Gate for saving a rule. Returns the URL, or raises WebhookTargetError.

    Passing here is necessary but not sufficient — `deliver_webhook` re-runs
    the same checks at send time, because DNS can change in between.
    """
    url = (url or "").strip()
    if not url:
        raise WebhookTargetError("Webhook URL is required")
    _prepare(url)
    return url


def _open_connection(hostname: str, port: int, pinned_ip: str) -> http.client.HTTPSConnection:
    """Dial `pinned_ip` but speak TLS and HTTP as `hostname`.

    Assigning the pre-built socket to `conn.sock` stops http.client from
    calling `connect()` — which would resolve the hostname a second time and
    reopen the rebinding window this function exists to close.
    """
    context = ssl.create_default_context()
    raw_sock = socket.create_connection((pinned_ip, port), timeout=TIMEOUT_SECONDS)
    try:
        tls_sock = context.wrap_socket(raw_sock, server_hostname=hostname)
    except Exception:
        raw_sock.close()
        raise
    conn = http.client.HTTPSConnection(hostname, port, timeout=TIMEOUT_SECONDS)
    conn.sock = tls_sock
    return conn


def deliver_webhook(url: str, payload: bytes) -> None:
    """POST `payload` to `url`, following validated redirects. Raises on failure."""
    method = "POST"
    body: bytes | None = payload

    for hop in range(MAX_REDIRECTS + 1):
        hostname, port, target, pinned_ip = _prepare(url)
        headers = {"Content-Type": "application/json"} if body else {}

        conn = _open_connection(hostname, port, pinned_ip)
        try:
            conn.request(method, target, body=body, headers=headers)
            response = conn.getresponse()
            status = response.status
            location = response.getheader("Location")
            response.read()  # drain and discard; never surfaced to a caller
        finally:
            conn.close()

        if status in _REDIRECT_CODES and location:
            if hop == MAX_REDIRECTS:
                raise WebhookTargetError(f"Too many webhook redirects (>{MAX_REDIRECTS})")
            url = urljoin(url, location)
            if status in _REDIRECT_DROPS_BODY:
                method, body = "GET", None
            continue

        if status >= 400:
            raise WebhookTargetError(f"Webhook endpoint returned HTTP {status}")
        return
