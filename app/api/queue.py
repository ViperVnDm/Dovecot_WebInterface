"""Mail queue management API routes."""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app.core.security import get_current_user
from app.core.permissions import get_helper_client, PrivilegedHelperError
from app.database import AdminUser
from app.templates_setup import templates

router = APIRouter()


def _format_bytes(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


async def _render_queue_table(request: Request):
    """Re-render the queue table partial after a mutating action (for HTMX).

    Queue action buttons (`hx-target="#queue-table"`) expect the refreshed
    table back, mirroring how app/api/users.py returns the user list.
    """
    helper = get_helper_client()
    try:
        messages = await helper.list_queue()
    except PrivilegedHelperError as e:
        return templates.TemplateResponse(
            request,
            "partials/error.html",
            {"error": f"Failed to load queue: {e.message}"},
        )
    return templates.TemplateResponse(
        request,
        "partials/queue_table.html",
        {"messages": messages, "format_bytes": _format_bytes},
    )


class QueuedMessage(BaseModel):
    """A message in the Postfix queue."""

    queue_id: str
    queue_name: str  # active, deferred, hold, incoming
    sender: str
    recipients: list[str]
    size: int
    arrival_time: datetime
    reason: str | None = None


class QueueStats(BaseModel):
    """Queue statistics."""

    active: int
    deferred: int
    hold: int
    incoming: int
    total: int


class MessageDetails(BaseModel):
    """Detailed information about a queued message."""

    queue_id: str
    queue_name: str
    sender: str
    recipients: list[str]
    size: int
    arrival_time: datetime
    reason: str | None = None
    headers: dict[str, str] | None = None


@router.get("")
async def list_queue(
    queue_name: str | None = Query(default=None, pattern="^(active|deferred|hold|incoming)$"),
    sender: str | None = None,
    recipient: str | None = None,
    current_user: AdminUser = Depends(get_current_user),
) -> list[QueuedMessage]:
    """List messages in the mail queue."""
    # TODO: Implement via privileged helper
    return []


@router.get("/stats")
async def get_queue_stats(
    current_user: AdminUser = Depends(get_current_user),
) -> QueueStats:
    """Get queue statistics."""
    # TODO: Implement via privileged helper
    return QueueStats(active=0, deferred=0, hold=0, incoming=0, total=0)


@router.get("/{queue_id}")
async def get_message(
    queue_id: str,
    current_user: AdminUser = Depends(get_current_user),
) -> MessageDetails:
    """Get details of a specific queued message."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")


@router.post("/flush")
async def flush_queue(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Flush the entire mail queue (attempt delivery of all messages)."""
    helper = get_helper_client()
    try:
        await helper.flush_queue()
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)
    return await _render_queue_table(request)


@router.post("/{queue_id}/flush")
async def flush_message(
    request: Request,
    queue_id: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Flush a specific message (attempt immediate delivery)."""
    helper = get_helper_client()
    try:
        await helper.flush_message(queue_id)
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)
    return await _render_queue_table(request)


@router.delete("/{queue_id}")
async def delete_message(
    request: Request,
    queue_id: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Delete a message from the queue."""
    helper = get_helper_client()
    try:
        await helper.delete_message(queue_id)
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)
    return await _render_queue_table(request)


@router.post("/{queue_id}/hold")
async def hold_message(
    request: Request,
    queue_id: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Put a message on hold."""
    helper = get_helper_client()
    try:
        await helper.hold_message(queue_id)
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)
    return await _render_queue_table(request)


@router.post("/{queue_id}/release")
async def release_message(
    request: Request,
    queue_id: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Release a message from hold."""
    helper = get_helper_client()
    try:
        await helper.release_message(queue_id)
    except PrivilegedHelperError as e:
        raise HTTPException(status_code=e.code, detail=e.message)
    return await _render_queue_table(request)
