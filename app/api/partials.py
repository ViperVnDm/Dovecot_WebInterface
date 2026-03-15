"""HTMX partial template routes."""

import logging
from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.security import get_current_user
from app.core.permissions import get_helper_client, PrivilegedHelperError
from app.database import get_db, AdminUser, AlertRule, AlertHistory

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


def format_bytes(size: int) -> str:
    """Format bytes to human readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


# ============== Dashboard Partials ==============


@router.get("/dashboard/stats")
async def dashboard_stats(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Dashboard statistics cards."""
    helper = get_helper_client()

    # Get data (with fallbacks)
    try:
        users = await helper.list_users()
        user_count = len(users)
    except PrivilegedHelperError:
        user_count = 0

    try:
        queue_stats = await helper.get_queue_stats()
        queue_total = queue_stats.get("total", 0)
        deferred = queue_stats.get("deferred", 0)
    except PrivilegedHelperError:
        queue_total = 0
        deferred = 0

    import shutil
    from app.config import get_settings
    settings = get_settings()

    try:
        usage = shutil.disk_usage(str(settings.mail_spool_path))
        storage_percent = round((usage.used / usage.total) * 100, 1)
    except Exception:
        storage_percent = 0

    return templates.TemplateResponse(
        "partials/dashboard_stats.html",
        {
            "request": request,
            "user_count": user_count,
            "queue_total": queue_total,
            "deferred": deferred,
            "storage_percent": storage_percent,
        },
    )


@router.get("/dashboard/queue-summary")
async def dashboard_queue_summary(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Queue summary for dashboard."""
    helper = get_helper_client()

    try:
        queue_stats = await helper.get_queue_stats()
        messages = await helper.list_queue()
    except PrivilegedHelperError:
        queue_stats = {"active": 0, "deferred": 0, "hold": 0, "incoming": 0, "total": 0}
        messages = []

    return templates.TemplateResponse(
        "partials/queue_summary.html",
        {
            "request": request,
            "stats": queue_stats,
            "recent_messages": messages[:5],
        },
    )


@router.get("/dashboard/storage-summary")
async def dashboard_storage_summary(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Storage summary for dashboard."""
    import shutil
    from app.config import get_settings

    settings = get_settings()

    try:
        usage = shutil.disk_usage(str(settings.mail_spool_path))
        disk_info = {
            "path": str(settings.mail_spool_path),
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": round((usage.used / usage.total) * 100, 1),
            "total_human": format_bytes(usage.total),
            "used_human": format_bytes(usage.used),
            "free_human": format_bytes(usage.free),
        }
    except Exception:
        disk_info = None

    return templates.TemplateResponse(
        "partials/storage_summary.html",
        {"request": request, "disk": disk_info, "format_bytes": format_bytes},
    )


@router.get("/dashboard/recent-activity")
async def dashboard_recent_activity(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Recent mail activity for dashboard."""
    helper = get_helper_client()

    try:
        logs = await helper.read_logs(lines=10)
    except PrivilegedHelperError:
        logs = []

    return templates.TemplateResponse(
        "partials/recent_activity.html",
        {"request": request, "logs": logs},
    )


@router.get("/dashboard/alerts")
async def dashboard_alerts(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Active alerts for dashboard."""
    # TODO: Implement alert checking
    alerts = []

    return templates.TemplateResponse(
        "partials/dashboard_alerts.html",
        {"request": request, "alerts": alerts},
    )


# ============== User Partials ==============


@router.get("/users/list")
async def users_list(
    request: Request,
    search: str = "",
    current_user: AdminUser = Depends(get_current_user),
):
    """User list table."""
    helper = get_helper_client()

    try:
        users = await helper.list_users()
        if search:
            users = [u for u in users if search.lower() in u["username"].lower()]
    except PrivilegedHelperError as e:
        return templates.TemplateResponse(
            "partials/error.html",
            {"request": request, "error": f"Failed to load users: {e.message}"},
        )

    return templates.TemplateResponse(
        "partials/users_list.html",
        {"request": request, "users": users, "format_bytes": format_bytes},
    )


# ============== Queue Partials ==============


@router.get("/queue/stats")
async def queue_stats(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Queue statistics cards."""
    helper = get_helper_client()

    try:
        stats = await helper.get_queue_stats()
    except PrivilegedHelperError:
        stats = {"active": 0, "deferred": 0, "hold": 0, "incoming": 0, "total": 0}

    return templates.TemplateResponse(
        "partials/queue_stats.html",
        {"request": request, "stats": stats},
    )


@router.get("/queue/table")
async def queue_table(
    request: Request,
    queue_name: str = "",
    search: str = "",
    current_user: AdminUser = Depends(get_current_user),
):
    """Queue messages table."""
    helper = get_helper_client()

    try:
        messages = await helper.list_queue(queue_name if queue_name else None)
        if search:
            search_lower = search.lower()
            messages = [
                m for m in messages
                if search_lower in m.get("sender", "").lower()
                or any(search_lower in r.lower() for r in m.get("recipients", []))
            ]
    except PrivilegedHelperError as e:
        return templates.TemplateResponse(
            "partials/error.html",
            {"request": request, "error": f"Failed to load queue: {e.message}"},
        )

    return templates.TemplateResponse(
        "partials/queue_table.html",
        {"request": request, "messages": messages, "format_bytes": format_bytes},
    )


# ============== Log Partials ==============


@router.get("/logs/stats")
async def logs_stats(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Log statistics cards."""
    helper = get_helper_client()
    try:
        stats = await helper.get_log_stats()
    except PrivilegedHelperError:
        stats = {"sent_today": 0, "received_today": 0, "bounced_today": 0, "errors_today": 0}

    return templates.TemplateResponse(
        "partials/logs_stats.html",
        {"request": request, "stats": stats},
    )


@router.get("/logs/banned")
async def logs_banned(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Banned IP list."""
    helper = get_helper_client()
    try:
        banned_ips = await helper.list_banned_ips()
    except PrivilegedHelperError:
        banned_ips = []

    return templates.TemplateResponse(
        "partials/logs_banned.html",
        {"request": request, "banned_ips": banned_ips},
    )


@router.get("/logs/entries")
async def logs_entries(
    request: Request,
    level: str = "",
    service: str = "",
    search: str = "",
    current_user: AdminUser = Depends(get_current_user),
):
    """Log entries list."""
    helper = get_helper_client()

    try:
        entries = await helper.read_logs(
            lines=200,
            level=level if level else None,
            service=service if service else None,
            search=search if search else None,
        )
    except PrivilegedHelperError as e:
        logger.error(f"Failed to read logs from helper: {e.message}")
        entries = []

    return templates.TemplateResponse(
        "partials/logs_entries.html",
        {"request": request, "entries": entries},
    )


# ============== Storage Partials ==============


@router.get("/storage/overview")
async def storage_overview(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Storage overview cards."""
    import shutil
    from app.config import get_settings

    settings = get_settings()

    try:
        usage = shutil.disk_usage(str(settings.mail_spool_path))
        disk_info = {
            "path": str(settings.mail_spool_path),
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": round((usage.used / usage.total) * 100, 1),
            "total_human": format_bytes(usage.total),
            "used_human": format_bytes(usage.used),
            "free_human": format_bytes(usage.free),
        }
    except Exception:
        disk_info = None

    # TODO: Get active alerts
    alerts = []

    return templates.TemplateResponse(
        "partials/storage_overview.html",
        {"request": request, "disk": disk_info, "alerts": alerts},
    )


@router.get("/storage/mailboxes")
async def storage_mailboxes(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Mailbox sizes list."""
    helper = get_helper_client()

    try:
        mailboxes = await helper.get_mailbox_sizes()
    except PrivilegedHelperError:
        mailboxes = []

    return templates.TemplateResponse(
        "partials/storage_mailboxes.html",
        {"request": request, "mailboxes": mailboxes[:20], "format_bytes": format_bytes},
    )


@router.get("/storage/history")
async def storage_history(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Storage usage history chart."""
    # TODO: Implement from database
    history = []

    return templates.TemplateResponse(
        "partials/storage_history.html",
        {"request": request, "history": history},
    )


# ============== Alert Partials ==============


@router.get("/alerts/active")
async def alerts_active(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Active alerts list."""
    alerts = []
    return templates.TemplateResponse(
        "partials/alerts_active.html",
        {"request": request, "alerts": alerts},
    )


@router.get("/alerts/rules")
async def alerts_rules(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Alert rules list."""
    result = await db.execute(select(AlertRule).order_by(AlertRule.created_at.desc()))
    rules = result.scalars().all()
    return templates.TemplateResponse(
        "partials/alerts_rules.html",
        {"request": request, "rules": rules},
    )


@router.get("/alerts/history")
async def alerts_history(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Alert history list."""
    result = await db.execute(
        select(AlertHistory)
        .options(selectinload(AlertHistory.rule))
        .order_by(AlertHistory.triggered_at.desc())
        .limit(50)
    )
    history = result.scalars().all()
    return templates.TemplateResponse(
        "partials/alerts_history.html",
        {"request": request, "history": history},
    )
