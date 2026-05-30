"""Mail queue management API routes."""

from fastapi import APIRouter, Depends, HTTPException, Request

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
