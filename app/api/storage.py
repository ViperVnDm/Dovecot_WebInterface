"""Storage monitoring API routes."""

from fastapi import APIRouter, Depends
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
