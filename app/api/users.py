"""User management API routes."""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.core.security import get_current_user
from app.core.permissions import get_helper_client, PrivilegedHelperError
from app.database import AdminUser

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


def _format_bytes(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


async def _render_users_list(request: Request):
    helper = get_helper_client()
    try:
        users = await helper.list_users()
    except PrivilegedHelperError:
        users = []
    return templates.TemplateResponse(
        "partials/users_list.html",
        {"request": request, "users": users, "format_bytes": _format_bytes},
    )


@router.post("")
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    quota_mb: int = Form(default=0),
    current_user: AdminUser = Depends(get_current_user),
):
    """Create a new mail user."""
    helper = get_helper_client()
    try:
        await helper.create_user(username, password, quota_mb)
    except PrivilegedHelperError as e:
        return templates.TemplateResponse(
            "partials/error.html",
            {"request": request, "error": e.message},
            status_code=400,
        )
    return await _render_users_list(request)


@router.post("/{username}/password")
async def set_password(
    request: Request,
    username: str,
    password: str = Form(...),
    current_user: AdminUser = Depends(get_current_user),
):
    """Change a user's password."""
    helper = get_helper_client()
    try:
        await helper.set_password(username, password)
    except PrivilegedHelperError as e:
        return templates.TemplateResponse(
            "partials/error.html",
            {"request": request, "error": e.message},
            status_code=400,
        )
    return await _render_users_list(request)


@router.delete("/{username}")
async def delete_user(
    request: Request,
    username: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Delete a mail user."""
    helper = get_helper_client()
    try:
        await helper.delete_user(username, delete_mail=False)
    except PrivilegedHelperError as e:
        return templates.TemplateResponse(
            "partials/error.html",
            {"request": request, "error": e.message},
            status_code=400,
        )
    return await _render_users_list(request)
