"""Audit-log helper.

Records privileged admin actions (user CRUD, IP bans, alert-rule changes, …)
to the `audit_log` table. Call `record_audit(...)` inside a route's DB session
and let the route commit — this keeps the audit row in the same transaction as
the change it describes.
"""

import json
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AuditLog


async def record_audit(
    db: AsyncSession,
    *,
    user_id: int | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    """Add an AuditLog row to the session. The caller is responsible for commit.

    `request` (if given) supplies the source IP — accurate now that uvicorn
    runs with --proxy-headers (see systemd unit / Step 3).
    """
    ip = None
    if request is not None and request.client is not None:
        ip = request.client.host
    db.add(AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=json.dumps(details) if details is not None else None,
        ip_address=ip,
    ))
