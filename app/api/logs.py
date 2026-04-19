"""Mail log viewing API routes."""

import ipaddress
from datetime import datetime
from enum import Enum
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.core.permissions import get_helper_client, PrivilegedHelperError
from app.database import get_db, AdminUser, AppSetting

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")

SETTING_BAN_ALLOWLIST = "ban_allowlist"


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


# ── Allowlist helpers ────────────────────────────────────────────────────────


def _parse_allowlist(raw: str) -> list[str]:
    return [e.strip() for e in raw.split(",") if e.strip()]


async def load_allowlist(db: AsyncSession) -> list[str]:
    """Return current allowlist entries from the DB."""
    result = await db.execute(
        select(AppSetting).where(AppSetting.key == SETTING_BAN_ALLOWLIST)
    )
    setting = result.scalar_one_or_none()
    return _parse_allowlist(setting.value) if setting else []


def is_allowlisted(ip: str, allowlist: list[str]) -> bool:
    """Return True if ip matches any allowlist entry (exact IP or CIDR)."""
    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allowlist:
        try:
            if "/" in entry:
                if ip_addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if ip_addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


async def _save_allowlist(db: AsyncSession, entries: list[str]) -> None:
    value = ",".join(entries)
    result = await db.execute(
        select(AppSetting).where(AppSetting.key == SETTING_BAN_ALLOWLIST)
    )
    setting = result.scalar_one_or_none()
    if setting:
        setting.value = value
    else:
        db.add(AppSetting(key=SETTING_BAN_ALLOWLIST, value=value))
    await db.commit()


def _ips_covered_by_cidr(cidr: str, ip_list: list[str]) -> list[str]:
    """Return IPs from ip_list that fall within the given CIDR range."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    covered = []
    for entry in ip_list:
        if "/" in entry:
            continue  # skip other CIDRs
        try:
            if ipaddress.ip_address(entry) in network:
                covered.append(entry)
        except ValueError:
            continue
    return covered


# ── Allowlist API ────────────────────────────────────────────────────────────


@router.post("/allowlist")
async def add_to_allowlist(
    request: Request,
    entry: str = Form(...),
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add an IP or CIDR to the ban allowlist."""
    entry = entry.strip()
    # Validate
    try:
        if "/" in entry:
            ipaddress.ip_network(entry, strict=False)
        else:
            ipaddress.ip_address(entry)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP/CIDR: {entry}")

    allowlist = await load_allowlist(db)
    if entry not in allowlist:
        allowlist.append(entry)
        # If adding a CIDR, remove individual IPs it covers
        if "/" in entry:
            covered = _ips_covered_by_cidr(entry, allowlist)
            allowlist = [e for e in allowlist if e not in covered]
        await _save_allowlist(db, allowlist)

    return templates.TemplateResponse(
        request, "partials/logs_allowlist.html",
        context={"allowlist": allowlist},
    )


@router.delete("/allowlist/{entry:path}")
async def remove_from_allowlist(
    request: Request,
    entry: str,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove an IP or CIDR from the ban allowlist."""
    allowlist = await load_allowlist(db)
    allowlist = [e for e in allowlist if e != entry]
    await _save_allowlist(db, allowlist)
    return templates.TemplateResponse(
        request, "partials/logs_allowlist.html",
        context={"allowlist": allowlist},
    )


# ── Ban/Unban API ────────────────────────────────────────────────────────────


@router.post("/ban-ip")
async def ban_ip(
    request: Request,
    ip: str = Form(...),
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Block an IP address or CIDR range via UFW (rejected if allowlisted)."""
    target = ip.strip()
    # For single IPs, check allowlist; for CIDRs, validate format
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid CIDR: {target}")
    else:
        allowlist = await load_allowlist(db)
        if is_allowlisted(target, allowlist):
            raise HTTPException(status_code=403, detail=f"{target} is in the never-ban allowlist")

    helper = get_helper_client()
    try:
        await helper.ban_ip(target)
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)

    # If banning a CIDR, remove individual IPs it covers from UFW
    if "/" in target:
        try:
            banned = await helper.list_banned_ips()
            covered = _ips_covered_by_cidr(target, banned)
            for covered_ip in covered:
                try:
                    await helper.unban_ip(covered_ip)
                except PrivilegedHelperError:
                    pass  # best-effort cleanup
        except PrivilegedHelperError:
            pass

    # Return updated banned IPs list for HTMX
    try:
        banned_ips = await helper.list_banned_ips()
    except PrivilegedHelperError:
        banned_ips = []
    return templates.TemplateResponse(
        request, "partials/logs_banned.html",
        context={"banned_ips": banned_ips},
    )


@router.delete("/ban-ip/{ip:path}")
async def unban_ip(
    request: Request,
    ip: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Remove a UFW ban for an IP address or CIDR range."""
    helper = get_helper_client()
    try:
        await helper.unban_ip(ip)
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)

    # Return updated banned IPs list for HTMX
    try:
        banned_ips = await helper.list_banned_ips()
    except PrivilegedHelperError:
        banned_ips = []
    return templates.TemplateResponse(
        request, "partials/logs_banned.html",
        context={"banned_ips": banned_ips},
    )


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


@router.get("/export")
async def export_ip_lists(
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export banned and never-banned IPs as a downloadable text file."""
    helper = get_helper_client()
    try:
        banned = await helper.list_banned_ips()
    except PrivilegedHelperError:
        banned = []
    allowlist = await load_allowlist(db)

    lines = ["# IP Ban/Allowlist Export", "#"]
    lines.append("# Banned IPs/CIDRs (UFW DENY rules)")
    if banned:
        for entry in banned:
            lines.append(entry)
    else:
        lines.append("# (none)")
    lines.append("#")
    lines.append("# Never-Ban Allowlist")
    if allowlist:
        for entry in allowlist:
            lines.append(entry)
    else:
        lines.append("# (none)")

    return PlainTextResponse(
        "\n".join(lines) + "\n",
        headers={"Content-Disposition": "attachment; filename=ip-lists-export.txt"},
    )


@router.get("")
async def get_logs(
    lines: int = Query(default=100, ge=1, le=1000),
    level: LogLevel | None = None,
    service: str | None = None,
    search: str | None = None,
    current_user: AdminUser = Depends(get_current_user),
) -> list[LogEntry]:
    """Get recent mail log entries."""
    return []


@router.websocket("/ws")
async def logs_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time log streaming."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        pass
