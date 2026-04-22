"""Security middleware: response headers and CSRF protection."""

from __future__ import annotations

import hmac
import secrets

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
        # CSP — relatively permissive because the templates load from CDNs.
        # Tightening this further (and self-hosting CDN assets) is a follow-up.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://cdn.tailwindcss.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
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
    """Double-submit-cookie CSRF protection.

    On safe requests we ensure a CSRF token cookie exists.
    On unsafe requests (POST/PUT/PATCH/DELETE) we require either:
      - an `X-CSRF-Token` header that matches the cookie, OR
      - a form field named `csrf_token` that matches the cookie.

    The login endpoint is exempt because it has no session yet — login is
    protected by rate limiting instead.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        cookie_name: str = "dwa_csrf",
        secure: bool = True,
    ) -> None:
        super().__init__(app)
        self._cookie_name = cookie_name
        self._secure = secure

    async def dispatch(self, request: Request, call_next):
        token_cookie = request.cookies.get(self._cookie_name)

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
            if not _tokens_match(token_cookie or "", submitted or ""):
                return JSONResponse(
                    {"error": "CSRF token missing or invalid"},
                    status_code=403,
                )

        response: Response = await call_next(request)

        if not token_cookie:
            new_token = _new_token()
            # Cookie is NOT HttpOnly — by design, JS reads it to send the
            # X-CSRF-Token header. Pair with SameSite=Strict to neutralise
            # cross-site abuse.
            response.set_cookie(
                key=self._cookie_name,
                value=new_token,
                httponly=False,
                secure=self._secure,
                samesite="strict",
                path="/",
                max_age=60 * 60 * 24,
            )
            # Make the new token visible to the current response context too,
            # so the rendered page (e.g. /login) can embed it.
            request.state.csrf_token = new_token
        else:
            request.state.csrf_token = token_cookie
        return response


def get_csrf_token(request: Request) -> str:
    """Return the active CSRF token for use in templates."""
    token = getattr(request.state, "csrf_token", None)
    if token:
        return token
    return request.cookies.get("dwa_csrf", "")
