"""Authentication routes."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.core.security import (
    verify_password,
    create_session,
    get_current_user,
    delete_session,
)
from app.config import get_settings
from app.database import get_db, AdminUser
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render login page."""
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "title": "Login"},
    )


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user and create session."""
    # Find user
    result = await db.execute(
        select(AdminUser).where(AdminUser.username == username)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "title": "Login",
                "error": "Invalid username or password",
            },
            status_code=401,
        )

    if not user.is_active:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "title": "Login",
                "error": "Account is disabled",
            },
            status_code=401,
        )

    # Create session
    session_token = await create_session(db, user.id, request)

    # Set session cookie and redirect
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(
        key="session",
        value=session_token,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite="lax",
        max_age=86400,  # 24 hours
    )
    return response


@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Destroy session and redirect to login."""
    session_token = request.cookies.get("session")
    if session_token:
        await delete_session(db, session_token)

    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session")
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
