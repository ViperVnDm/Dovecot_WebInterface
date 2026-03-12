"""User management API routes."""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
import re

from app.core.security import get_current_user
from app.database import AdminUser

router = APIRouter()


class CreateUserRequest(BaseModel):
    """Request model for creating a mail user."""

    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8, max_length=128)
    quota_mb: int = Field(default=0, ge=0, le=102400)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-z][a-z0-9_-]*$", v):
            raise ValueError(
                "Username must start with letter, contain only lowercase, numbers, underscores, hyphens"
            )
        if v in ["root", "admin", "postfix", "dovecot", "mail", "nobody", "daemon"]:
            raise ValueError("Reserved username")
        return v


class UpdateUserRequest(BaseModel):
    """Request model for updating a mail user."""

    password: str | None = Field(default=None, min_length=8, max_length=128)
    quota_mb: int | None = Field(default=None, ge=0, le=102400)


class MailUser(BaseModel):
    """Response model for a mail user."""

    username: str
    uid: int
    gid: int
    home: str
    quota_mb: int | None = None
    quota_used_mb: float | None = None


@router.get("")
async def list_users(
    current_user: AdminUser = Depends(get_current_user),
) -> list[MailUser]:
    """List all mail users."""
    # TODO: Implement via privileged helper
    return []


@router.post("", status_code=201)
async def create_user(
    request: CreateUserRequest,
    current_user: AdminUser = Depends(get_current_user),
) -> MailUser:
    """Create a new mail user."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")


@router.get("/{username}")
async def get_user(
    username: str,
    current_user: AdminUser = Depends(get_current_user),
) -> MailUser:
    """Get a specific mail user."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")


@router.put("/{username}")
async def update_user(
    username: str,
    request: UpdateUserRequest,
    current_user: AdminUser = Depends(get_current_user),
) -> MailUser:
    """Update a mail user (password, quota)."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")


@router.delete("/{username}", status_code=204)
async def delete_user(
    username: str,
    delete_mail: bool = Query(default=False),
    current_user: AdminUser = Depends(get_current_user),
):
    """Delete a mail user."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")


@router.get("/{username}/quota")
async def get_user_quota(
    username: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Get quota usage for a user."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")
