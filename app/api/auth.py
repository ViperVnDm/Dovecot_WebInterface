"""Authentication routes."""

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.security import (
    verify_password,
    create_session,
    get_current_user,
    delete_session,
    hash_password,
)
from app.core.limiter import limiter
from app.config import get_settings
from app.database import get_db, AdminUser
from app.templates_setup import templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

router = APIRouter()
_settings = get_settings()
# A constant-time fallback hash so login timing doesn't leak whether the
# username exists. Generated once on import.
_DUMMY_HASH = hash_password("dummy-password-for-timing-equalisation")

DEFAULT_POST_LOGIN_PATH = "/dashboard"


def _safe_next(value: str | None) -> str:
    """Sanitise the `?next=` / `next` form value into a local path.

    Only same-origin *relative* paths are honoured — anything else falls back
    to the dashboard. This is the open-redirect gate: the value reaches us
    from the URL bar, so an attacker can hand a victim a login link that would
    otherwise bounce them to a lookalike host after a genuine login.

    Rejected, specifically:
      - `//evil.com` and `/\\evil.com` — protocol-relative URLs. Browsers
        normalise the backslash form to `//`, so any backslash is refused.
      - `https://evil.com`, `javascript:…` — anything not starting with `/`.
      - control characters, which can smuggle a second header past a proxy.
      - `/login*`, which would bounce a just-authenticated user back to the
        login form.
    """
    if not value or not value.startswith("/"):
        return DEFAULT_POST_LOGIN_PATH
    if value.startswith("//") or "\\" in value:
        return DEFAULT_POST_LOGIN_PATH
    if any(ch < " " or ch == "\x7f" for ch in value):
        return DEFAULT_POST_LOGIN_PATH
    if value == "/login" or value.startswith("/login?"):
        return DEFAULT_POST_LOGIN_PATH
    return value


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    next_url: str = Query("", alias="next"),
):
    """Render login page."""
    return templates.TemplateResponse(
        request,
        "login.html",
        {"title": "Login", "next_url": _safe_next(next_url)},
    )


@router.post("/login")
@limiter.limit(_settings.login_rate_limit)
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    next_url: str = Form("", alias="next"),
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user and create session."""
    settings = get_settings()
    next_url = _safe_next(next_url)

    # Find user
    result = await db.execute(
        select(AdminUser).where(AdminUser.username == username)
    )
    user = result.scalar_one_or_none()

    # Always run bcrypt to neutralise username-enumeration timing oracle.
    if user is None:
        verify_password(password, _DUMMY_HASH)
        password_ok = False
    else:
        password_ok = verify_password(password, user.password_hash)

    if user is None or not password_ok or not user.is_active:
        # Identical error for unknown user, wrong password, and disabled
        # account so the response doesn't leak which condition failed.
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "title": "Login",
                "error": "Invalid username or password",
                # Keep the destination across a failed attempt.
                "next_url": next_url,
            },
            status_code=401,
        )

    # Create session
    session_token = await create_session(db, user.id, request)

    # Set session cookie and redirect
    response = RedirectResponse(url=next_url, status_code=302)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=settings.session_expire_hours * 3600,
    )
    return response


@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Destroy session and redirect to login."""
    settings = get_settings()
    session_token = request.cookies.get(settings.session_cookie_name)
    if session_token:
        await delete_session(db, session_token)

    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(
        settings.session_cookie_name,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
    )
    return response


@router.get("/api/auth/me")
async def get_me(
    current_user: AdminUser = Depends(get_current_user),
):
    """Get current authenticated user info."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
    }
