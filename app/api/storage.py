"""Storage monitoring API routes."""

from datetime import datetime
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.core.security import get_current_user
from app.database import AdminUser

router = APIRouter()


class DiskUsage(BaseModel):
    """Disk usage information."""

    path: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent_used: float


class MailboxSize(BaseModel):
    """Mailbox size for a user."""

    username: str
    size_bytes: int
    message_count: int


class UsagePoint(BaseModel):
    """Historical usage data point."""

    timestamp: datetime
    used_bytes: int
    total_bytes: int


class StorageAlert(BaseModel):
    """Active storage alert."""

    id: int
    rule_name: str
    current_value: float
    threshold_value: float
    message: str
    triggered_at: datetime


@router.get("/disk")
async def get_disk_usage(
    current_user: AdminUser = Depends(get_current_user),
) -> DiskUsage:
    """Get disk usage for the configured mail spool path.

    The path is fixed to `settings.mail_spool_path` — accepting an arbitrary
    path from the client allowed authenticated users to probe any filesystem
    location and was removed.
    """
    import shutil

    from app.config import get_settings

    settings = get_settings()
    target_path = str(settings.mail_spool_path)

    try:
        usage = shutil.disk_usage(target_path)
        return DiskUsage(
            path=target_path,
            total_bytes=usage.total,
            used_bytes=usage.used,
            free_bytes=usage.free,
            percent_used=round((usage.used / usage.total) * 100, 2),
        )
    except Exception:
        return DiskUsage(
            path=target_path,
            total_bytes=0,
            used_bytes=0,
            free_bytes=0,
            percent_used=0,
        )


@router.get("/mailboxes")
async def get_mailbox_sizes(
    current_user: AdminUser = Depends(get_current_user),
) -> list[MailboxSize]:
    """Get size of each user's mailbox."""
    # TODO: Implement via privileged helper
    return []


@router.get("/history")
async def get_usage_history(
    days: int = Query(default=30, ge=1, le=365),
    current_user: AdminUser = Depends(get_current_user),
) -> list[UsagePoint]:
    """Get historical storage usage."""
    # TODO: Implement from database
    return []


@router.get("/alerts")
async def get_storage_alerts(
    current_user: AdminUser = Depends(get_current_user),
) -> list[StorageAlert]:
    """Get current storage alerts."""
    # TODO: Implement from database
    return []
