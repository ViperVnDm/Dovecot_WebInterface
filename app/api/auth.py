"""Authentication routes."""

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
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


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render login page."""
    return templates.TemplateResponse(
        request,
        "login.html",
        {"title": "Login"},
    )


@router.post("/login")
@limiter.limit(_settings.login_rate_limit)
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user and create session."""
    settings = get_settings()

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
            },
            status_code=401,
        )

    # Create session
    session_token = await create_session(db, user.id, request)

    # Set session cookie and redirect
    response = RedirectResponse(url="/dashboard", status_code=302)
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
