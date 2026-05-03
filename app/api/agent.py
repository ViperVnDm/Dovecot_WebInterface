"""Log-triage agent API routes.

The background loop in app/services/log_agent.py writes BanSuggestion rows.
These routes let an authenticated admin review them, approve (which calls
the privileged helper to apply a ban or appends to the never-ban list), or
reject. Also surfaces run history and runtime settings.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.logs import (
    SETTING_BAN_ALLOWLIST,
    _ips_covered_by_cidr,
    _parse_allowlist,
    is_allowlisted,
    load_allowlist,
)
from app.core.permissions import PrivilegedHelperError, get_helper_client
from app.core.security import get_current_user
from app.database import (
    AdminUser,
    AppSetting,
    AuditLog,
    BanSuggestion,
    LogAgentRun,
    get_db,
)
from app.services import log_agent
from app.services.log_agent import (
    SETTING_AGENT_DAILY_COST_DATE,
    SETTING_AGENT_DAILY_COST_USD,
    SETTING_AGENT_ENABLED,
    SETTING_AGENT_INTERVAL_MIN,
)
from app.templates_setup import templates

router = APIRouter()


# ── Suggestions list / approve / reject ──────────────────────────────────────


@router.get("/suggestions")
async def list_suggestions(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """HTMX partial — pending suggestions, newest first."""
    result = await db.execute(
        select(BanSuggestion)
        .where(BanSuggestion.status == "pending")
        .order_by(desc(BanSuggestion.created_at))
    )
    rows = result.scalars().all()
    suggestions = []
    for row in rows:
        try:
            evidence = json.loads(row.evidence) if row.evidence else []
        except json.JSONDecodeError:
            evidence = []
        suggestions.append({
            "id": row.id,
            "target": row.target,
            "action": row.action,
            "confidence": row.confidence,
            "reason": row.reason,
            "evidence": evidence,
            "created_at": row.created_at,
        })
    return templates.TemplateResponse(
        request,
        "partials/agent_suggestions.html",
        context={"suggestions": suggestions},
    )


async def _audit(db: AsyncSession, user_id: int, action: str, suggestion: BanSuggestion) -> None:
    db.add(AuditLog(
        user_id=user_id,
        action=action,
        resource_type="ban_suggestion",
        resource_id=str(suggestion.id),
        details=json.dumps({
            "target": suggestion.target,
            "suggested_action": suggestion.action,
            "confidence": suggestion.confidence,
        }),
    ))


@router.post("/suggestions/{suggestion_id}/approve")
async def approve_suggestion(
    request: Request,
    suggestion_id: int,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Apply a pending suggestion. Ban → helper.ban_ip; allowlist → append to setting."""
    suggestion = await db.get(BanSuggestion, suggestion_id)
    if suggestion is None or suggestion.status != "pending":
        raise HTTPException(404, "Suggestion not found or already reviewed")

    target = suggestion.target.strip()

    if suggestion.action == "ban":
        # Defense-in-depth: re-check allowlist client-side. Helper also validates.
        allowlist = await load_allowlist(db)
        if "/" not in target and is_allowlisted(target, allowlist):
            raise HTTPException(403, f"{target} is on the never-ban allowlist")
        helper = get_helper_client()
        try:
            await helper.ban_ip(target)
        except PrivilegedHelperError as e:
            raise HTTPException(status_code=e.code, detail=e.message)
    elif suggestion.action == "allowlist":
        # Validate then append.
        try:
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target)
        except ValueError:
            raise HTTPException(400, f"Invalid IP/CIDR in suggestion: {target}")
        allowlist = await load_allowlist(db)
        if target not in allowlist:
            allowlist.append(target)
            if "/" in target:
                covered = _ips_covered_by_cidr(target, allowlist)
                allowlist = [e for e in allowlist if e not in covered]
            value = ",".join(allowlist)
            row = (await db.execute(
                select(AppSetting).where(AppSetting.key == SETTING_BAN_ALLOWLIST)
            )).scalar_one_or_none()
            if row:
                row.value = value
            else:
                db.add(AppSetting(key=SETTING_BAN_ALLOWLIST, value=value))
    else:
        raise HTTPException(400, f"Unknown suggestion action: {suggestion.action}")

    suggestion.status = "approved"
    suggestion.reviewed_by = current_user.id
    suggestion.reviewed_at = datetime.now(timezone.utc)
    await _audit(db, current_user.id, "approve_suggestion", suggestion)
    await db.commit()

    return await list_suggestions(request, current_user=current_user, db=db)


@router.post("/suggestions/{suggestion_id}/reject")
async def reject_suggestion(
    request: Request,
    suggestion_id: int,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a suggestion rejected without applying anything."""
    suggestion = await db.get(BanSuggestion, suggestion_id)
    if suggestion is None or suggestion.status != "pending":
        raise HTTPException(404, "Suggestion not found or already reviewed")

    suggestion.status = "rejected"
    suggestion.reviewed_by = current_user.id
    suggestion.reviewed_at = datetime.now(timezone.utc)
    await _audit(db, current_user.id, "reject_suggestion", suggestion)
    await db.commit()
    return await list_suggestions(request, current_user=current_user, db=db)


# ── Run-now / runs history ───────────────────────────────────────────────────


@router.post("/run-now")
async def run_now(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger one agent iteration, bypassing the enabled flag."""
    asyncio.create_task(log_agent.run_once(force=True))
    return await list_runs(request, current_user=current_user, db=db)


@router.get("/runs")
async def list_runs(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """HTMX partial — last 20 agent runs."""
    result = await db.execute(
        select(LogAgentRun).order_by(desc(LogAgentRun.started_at)).limit(20)
    )
    runs = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "partials/agent_runs.html",
        context={"runs": runs},
    )


# ── Settings ─────────────────────────────────────────────────────────────────


async def _read_settings(db: AsyncSession) -> dict:
    keys = (
        SETTING_AGENT_ENABLED,
        SETTING_AGENT_INTERVAL_MIN,
        SETTING_AGENT_DAILY_COST_USD,
        SETTING_AGENT_DAILY_COST_DATE,
    )
    result = await db.execute(select(AppSetting).where(AppSetting.key.in_(keys)))
    rows = {r.key: r.value for r in result.scalars().all()}
    return {
        "enabled": rows.get(SETTING_AGENT_ENABLED, "false").lower() in ("1", "true", "yes"),
        "interval_min": int(rows.get(SETTING_AGENT_INTERVAL_MIN, "10") or 10),
        "today_cost_usd": float(rows.get(SETTING_AGENT_DAILY_COST_USD, "0") or 0),
        "today_cost_date": rows.get(SETTING_AGENT_DAILY_COST_DATE, ""),
    }


@router.get("/settings")
async def get_agent_settings(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    cfg = await _read_settings(db)
    return templates.TemplateResponse(
        request,
        "partials/agent_settings.html",
        context={"cfg": cfg},
    )


@router.post("/settings")
async def update_agent_settings(
    request: Request,
    enabled: str = Form("false"),
    interval_min: int = Form(10),
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if interval_min < 1 or interval_min > 1440:
        raise HTTPException(400, "interval_min must be between 1 and 1440")
    enabled_value = "true" if enabled.lower() in ("1", "true", "yes", "on") else "false"

    for key, value in (
        (SETTING_AGENT_ENABLED, enabled_value),
        (SETTING_AGENT_INTERVAL_MIN, str(interval_min)),
    ):
        row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
        if row:
            row.value = value
        else:
            db.add(AppSetting(key=key, value=value))
    await db.commit()
    return await get_agent_settings(request, current_user=current_user, db=db)
