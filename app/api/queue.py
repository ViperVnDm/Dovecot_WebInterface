"""Mail queue management API routes."""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core.security import get_current_user
from app.database import AdminUser

router = APIRouter()


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
    queue_name: str | None = Query(default=None, regex="^(active|deferred|hold|incoming)$"),
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


@router.post("/flush", status_code=204)
async def flush_queue(
    current_user: AdminUser = Depends(get_current_user),
):
    """Flush the entire mail queue (attempt delivery of all messages)."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")


@router.post("/{queue_id}/flush", status_code=204)
async def flush_message(
    queue_id: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Flush a specific message (attempt immediate delivery)."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")


@router.delete("/{queue_id}", status_code=204)
async def delete_message(
    queue_id: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Delete a message from the queue."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")


@router.post("/{queue_id}/hold", status_code=204)
async def hold_message(
    queue_id: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Put a message on hold."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")


@router.post("/{queue_id}/release", status_code=204)
async def release_message(
    queue_id: str,
    current_user: AdminUser = Depends(get_current_user),
):
    """Release a message from hold."""
    # TODO: Implement via privileged helper
    raise HTTPException(status_code=501, detail="Not implemented")
