"""Mail log viewing API routes."""

from datetime import datetime
from enum import Enum
from fastapi import APIRouter, Depends, Form, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.core.security import get_current_user
from app.core.permissions import get_helper_client, PrivilegedHelperError
from app.database import AdminUser

router = APIRouter()


class LogLevel(str, Enum):
    """Log entry severity level."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class LogEntry(BaseModel):
    """A parsed mail log entry."""

    timestamp: datetime
    host: str
    service: str  # postfix/smtp, dovecot, etc.
    pid: int | None = None
    level: LogLevel = LogLevel.INFO
    message: str
    queue_id: str | None = None
    sender: str | None = None
    recipient: str | None = None
    status: str | None = None


class DeliveryStats(BaseModel):
    """Email delivery statistics."""

    period: str  # "day", "week", "month"
    sent: int
    deferred: int
    bounced: int
    rejected: int


class ConnectionStats(BaseModel):
    """Connection statistics."""

    period: str
    smtp_connections: int
    imap_connections: int
    pop3_connections: int
    successful_logins: int
    failed_logins: int


@router.get("")
async def get_logs(
    lines: int = Query(default=100, ge=1, le=1000),
    level: LogLevel | None = None,
    service: str | None = None,
    search: str | None = None,
    current_user: AdminUser = Depends(get_current_user),
) -> list[LogEntry]:
    """Get recent mail log entries."""
    # TODO: Implement via privileged helper
    return []


@router.get("/search")
async def search_logs(
    query: str,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    current_user: AdminUser = Depends(get_current_user),
) -> list[LogEntry]:
    """Search mail logs."""
    # TODO: Implement via privileged helper
    return []


@router.get("/stats/delivery")
async def get_delivery_stats(
    period: str = Query(default="day", regex="^(day|week|month)$"),
    current_user: AdminUser = Depends(get_current_user),
) -> DeliveryStats:
    """Get email delivery statistics."""
    # TODO: Implement via privileged helper
    return DeliveryStats(
        period=period, sent=0, deferred=0, bounced=0, rejected=0
    )


@router.get("/stats/connections")
async def get_connection_stats(
    period: str = Query(default="day", regex="^(day|week|month)$"),
    current_user: AdminUser = Depends(get_current_user),
) -> ConnectionStats:
    """Get connection statistics."""
    # TODO: Implement via privileged helper
    return ConnectionStats(
        period=period,
        smtp_connections=0,
        imap_connections=0,
        pop3_connections=0,
        successful_logins=0,
        failed_logins=0,
    )


@router.post("/ban-ip")
async def ban_ip(
    ip: str = Form(...),
    current_user: AdminUser = Depends(get_current_user),
) -> dict:
    """Block an IP address via UFW."""
    helper = get_helper_client()
    try:
        return await helper.ban_ip(ip)
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


@router.delete("/ban-ip/{ip}")
async def unban_ip(
    ip: str,
    current_user: AdminUser = Depends(get_current_user),
) -> dict:
    """Remove a UFW ban for an IP address."""
    helper = get_helper_client()
    try:
        return await helper.unban_ip(ip)
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


@router.get("/banned-ips")
async def list_banned_ips(
    current_user: AdminUser = Depends(get_current_user),
) -> dict:
    """List IPs currently blocked by UFW."""
    helper = get_helper_client()
    try:
        ips = await helper.list_banned_ips()
        return {"banned_ips": ips}
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


@router.websocket("/ws")
async def logs_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time log streaming."""
    await websocket.accept()
    try:
        # TODO: Implement real-time log streaming via privileged helper
        while True:
            # Keep connection alive, send logs as they come
            data = await websocket.receive_text()
            # Handle any client messages (e.g., filter changes)
    except WebSocketDisconnect:
        pass
