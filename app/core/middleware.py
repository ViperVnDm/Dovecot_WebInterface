"""Security middleware: response headers and CSRF protection."""

from __future__ import annotations

import hmac
import secrets
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Endpoints exempt from CSRF protection. The login form has no session yet,
# so a CSRF token can't be bound to it; rate limiting protects this path.
CSRF_EXEMPT_PATHS = frozenset({"/login"})


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _tokens_match(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a, b)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds defence-in-depth response headers to every response."""

    def __init__(self, app: ASGIApp, *, hsts: bool = True) -> None:
        super().__init__(app)
        self._hsts = hsts

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        # Don't override headers explicitly set by the route.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=()",
        )
        # CSP — every asset is self-hosted (app/static/), so no third-party
        # origin is trusted. 'unsafe-eval' remains because Alpine evaluates
        # x-data/x-on expressions and htmx evaluates hx-trigger filters with
        # Function(); 'unsafe-inline' because templates use inline <script>
        # and on* handlers. Removing either means the Alpine CSP build plus
        # moving that code into static files.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        if self._hsts:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains",
            )
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit-cookie CSRF protection, bound to the session.

    On unsafe requests (POST/PUT/PATCH/DELETE) we require either:
      - an `X-CSRF-Token` header that matches the cookie, OR
      - a form field named `csrf_token` that matches the cookie.

    Once the client has a session, the token must additionally equal
    `bind(session_token)` (HMAC with SECRET_KEY — see
    `csrf_token_for_session`). A plain double-submit cookie is only as strong
    as the guarantee that an attacker can't *write* that cookie; binding it to
    the HttpOnly session cookie removes that dependency. A client whose cookie
    doesn't match (e.g. the anonymous one from the login page) is re-issued
    the bound token on its next request, which is the GET that follows login.

    The token for this request is put on `request.state.csrf_token` *before*
    the route runs, so the page being rendered embeds the token the response
    is about to set.

    The login endpoint is exempt because it has no session yet — login is
    protected by rate limiting instead.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        cookie_name: str,
        session_cookie_name: str,
        bind: Callable[[str], str],
        secure: bool = True,
    ) -> None:
        super().__init__(app)
        self._cookie_name = cookie_name
        self._session_cookie_name = session_cookie_name
        self._bind = bind
        self._secure = secure

    async def dispatch(self, request: Request, call_next):
        token_cookie = request.cookies.get(self._cookie_name)
        session_token = request.cookies.get(self._session_cookie_name)
        expected = self._bind(session_token) if session_token else None

        if request.method not in SAFE_METHODS and request.url.path not in CSRF_EXEMPT_PATHS:
            header_token = request.headers.get("X-CSRF-Token")
            form_token: str | None = None
            if not header_token:
                # Best-effort form parse for HTML form submissions
                ctype = request.headers.get("content-type", "")
                if "application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype:
                    try:
                        form = await request.form()
                        form_token = form.get("csrf_token")  # type: ignore[assignment]
                    except Exception:
                        form_token = None
            submitted = header_token or form_token
            if not _tokens_match(token_cookie or "", submitted or "") or (
                expected is not None and not _tokens_match(token_cookie or "", expected)
            ):
                return JSONResponse(
                    {"error": "CSRF token missing or invalid"},
                    status_code=403,
                )

        token = expected or token_cookie or _new_token()
        request.state.csrf_token = token

        response: Response = await call_next(request)

        if token != token_cookie:
            # Cookie is NOT HttpOnly — by design, JS reads it to send the
            # X-CSRF-Token header. Pair with SameSite=Strict to neutralise
            # cross-site abuse.
            response.set_cookie(
                key=self._cookie_name,
                value=token,
                httponly=False,
                secure=self._secure,
                samesite="strict",
                path="/",
                max_age=60 * 60 * 24,
            )
        return response


def get_csrf_token(request: Request) -> str:
    """Return the active CSRF token for use in templates."""
    return getattr(request.state, "csrf_token", "") or ""
