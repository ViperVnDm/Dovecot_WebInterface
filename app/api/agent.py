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
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

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
    DEFAULT_AUTO_BAN_MIN_CONFIDENCE,
    SETTING_AGENT_AUTO_BAN_ENABLED,
    SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE,
    SETTING_AGENT_DAILY_COST_DATE,
    SETTING_AGENT_DAILY_COST_USD,
    SETTING_AGENT_ENABLED,
    SETTING_AGENT_INTERVAL_MIN,
)
from app.templates_setup import templates

router = APIRouter()


# ── Suggestions list / approve / reject ──────────────────────────────────────

# Sort options for the pending list. Keys are the accepted ?sort= values;
# anything else falls back to the default rather than 400-ing, because the
# value round-trips through user-editable URLs and a bad one should not break
# the page.
SUGGESTION_SORTS = ("network", "confidence", "newest", "oldest")
DEFAULT_SUGGESTION_SORT = "network"


def _network_key(target: str) -> tuple[int, int, int, int]:
    """Numeric sort key for an IP or CIDR target.

    A plain string sort does cluster shared prefixes correctly, but it orders
    the groups nonsensically ("23.x" sorts after "195.x") and misorders within
    a group (".9" after ".86"). ip_network gives true numeric order and handles
    both bare IPs and CIDRs. Unparseable targets sort last instead of raising —
    the column is free text as far as the database is concerned.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return (1, 0, 0, 0)
    return (0, net.version, int(net.network_address), net.prefixlen)


def _requested_sort(request: Request) -> str:
    """Read ?sort= off the request, falling back to the default when absent
    or unrecognised.

    Taken from the request rather than a function argument because the four
    approve/reject handlers re-render the list by calling list_suggestions()
    directly with their own Request; reading it here means their signatures do
    not have to change.
    """
    value = request.query_params.get("sort", DEFAULT_SUGGESTION_SORT)
    return value if value in SUGGESTION_SORTS else DEFAULT_SUGGESTION_SORT


@router.get("/suggestions")
async def list_suggestions(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """HTMX partial — pending suggestions in the order given by ?sort=."""
    return await _render_suggestions(request, db)


async def _render_suggestions(
    request: Request, db: AsyncSession, notice: str | None = None
):
    """Render the pending list. `notice` is a one-line result summary shown
    above the list after a bulk action (e.g. which targets failed to apply)."""
    sort = _requested_sort(request)

    # Time ordering stays in SQL. The network/confidence sorts are then applied
    # in Python on top of it: Python's sort is stable, so equal keys keep the
    # recency order underneath, and comparing datetimes in Python is avoided
    # entirely (SQLite has no native tz-aware type, so created_at can come back
    # naive and would not compare against an aware value).
    time_order = (
        BanSuggestion.created_at.asc()
        if sort == "oldest"
        else desc(BanSuggestion.created_at)
    )
    result = await db.execute(
        select(BanSuggestion)
        .where(BanSuggestion.status == "pending")
        .order_by(time_order)
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

    if sort == "network":
        suggestions.sort(key=lambda s: _network_key(s["target"]))
    elif sort == "confidence":
        suggestions.sort(key=lambda s: s["confidence"], reverse=True)

    return templates.TemplateResponse(
        request,
        "partials/agent_suggestions.html",
        context={"suggestions": suggestions, "sort": sort, "notice": notice},
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


class _ApplyError(Exception):
    """A suggestion could not be applied. Carries the HTTP status the
    single-approve route should return; bulk routes report it instead."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


async def _apply_suggestion(suggestion: BanSuggestion, allowlist: list[str]) -> bool:
    """Carry out a pending suggestion's action.

    Ban → helper.ban_ip. Allowlist → mutates `allowlist` in place; the caller
    persists it with _save_allowlist() (once, so a bulk approve writes the
    setting a single time). Returns True when `allowlist` was changed.
    Raises _ApplyError on anything that should leave the suggestion pending.
    """
    target = suggestion.target.strip()

    if suggestion.action == "ban":
        # Defense-in-depth: re-check allowlist client-side. Helper also validates.
        if "/" not in target and is_allowlisted(target, allowlist):
            raise _ApplyError(403, f"{target} is on the never-ban allowlist")
        try:
            await get_helper_client().ban_ip(target)
        except PrivilegedHelperError as e:
            raise _ApplyError(e.code, e.message)
        return False

    if suggestion.action == "allowlist":
        try:
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target)
        except ValueError:
            raise _ApplyError(400, f"Invalid IP/CIDR in suggestion: {target}")
        if target in allowlist:
            return False
        allowlist.append(target)
        if "/" in target:
            covered = _ips_covered_by_cidr(target, allowlist)
            allowlist[:] = [e for e in allowlist if e not in covered]
        return True

    raise _ApplyError(400, f"Unknown suggestion action: {suggestion.action}")


async def _save_allowlist(db: AsyncSession, allowlist: list[str]) -> None:
    value = ",".join(allowlist)
    row = (await db.execute(
        select(AppSetting).where(AppSetting.key == SETTING_BAN_ALLOWLIST)
    )).scalar_one_or_none()
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=SETTING_BAN_ALLOWLIST, value=value))


def _mark_reviewed(suggestion: BanSuggestion, status: str, user_id: int, now: datetime) -> None:
    suggestion.status = status
    suggestion.reviewed_by = user_id
    suggestion.reviewed_at = now


async def _pending_by_ids(db: AsyncSession, ids: list[int]) -> list[BanSuggestion]:
    """The still-pending suggestions among `ids`. Ids that were already
    reviewed (e.g. by another admin, or the 30-day expiry) are dropped."""
    result = await db.execute(
        select(BanSuggestion).where(
            BanSuggestion.id.in_(set(ids)),
            BanSuggestion.status == "pending",
        )
    )
    return list(result.scalars().all())


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

    allowlist = await load_allowlist(db)
    try:
        if await _apply_suggestion(suggestion, allowlist):
            await _save_allowlist(db, allowlist)
    except _ApplyError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    _mark_reviewed(suggestion, "approved", current_user.id, datetime.now(timezone.utc))
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


@router.post("/suggestions/approve-selected")
async def approve_selected_suggestions(
    request: Request,
    ids: list[int] = Form(default=[]),
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Apply every checked suggestion (bans and allowlist additions).

    Best-effort, like approve-all-bans: a target that fails to apply stays
    pending and is named in the result notice, the rest still go through.
    Allowlist actions run first so a ban in the same batch for a target that
    is also being allowlisted is refused rather than applied.
    """
    if not ids:
        raise HTTPException(400, "No suggestions selected")

    pending = await _pending_by_ids(db, ids)
    pending.sort(key=lambda s: s.action != "allowlist")  # stable: allowlist first

    allowlist = await load_allowlist(db)
    allowlist_changed = False
    now = datetime.now(timezone.utc)
    applied = 0
    failed: list[str] = []

    for suggestion in pending:
        try:
            allowlist_changed |= await _apply_suggestion(suggestion, allowlist)
        except _ApplyError as e:
            logger.warning("approve-selected: %s %s failed: %s",
                           suggestion.action, suggestion.target, e.detail)
            failed.append(suggestion.target)
            continue
        _mark_reviewed(suggestion, "approved", current_user.id, now)
        await _audit(db, current_user.id, "approve_suggestion", suggestion)
        applied += 1

    if allowlist_changed:
        await _save_allowlist(db, allowlist)

    stale = len(set(ids)) - len(pending)
    db.add(AuditLog(
        user_id=current_user.id,
        action="approve_selected_suggestions",
        resource_type="ban_suggestion",
        resource_id="*",
        details=json.dumps({"applied": applied, "failed": failed, "already_reviewed": stale}),
    ))
    await db.commit()

    notice = f"Approved {applied}."
    if failed:
        notice += f" Failed (left pending): {', '.join(failed)}."
    if stale:
        notice += f" {stale} already reviewed."
    return await _render_suggestions(request, db, notice=notice)


@router.post("/suggestions/reject-selected")
async def reject_selected_suggestions(
    request: Request,
    ids: list[int] = Form(default=[]),
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark every checked suggestion rejected without applying anything."""
    if not ids:
        raise HTTPException(400, "No suggestions selected")

    pending = await _pending_by_ids(db, ids)
    now = datetime.now(timezone.utc)
    for suggestion in pending:
        _mark_reviewed(suggestion, "rejected", current_user.id, now)
        await _audit(db, current_user.id, "reject_suggestion", suggestion)
    await db.commit()

    notice = f"Rejected {len(pending)}."
    stale = len(set(ids)) - len(pending)
    if stale:
        notice += f" {stale} already reviewed."
    return await _render_suggestions(request, db, notice=notice)


@router.post("/suggestions/approve-all-bans")
async def approve_all_ban_suggestions(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Approve every pending ban suggestion. Calls helper.ban_ip for each target."""
    result = await db.execute(
        select(BanSuggestion).where(
            BanSuggestion.status == "pending",
            BanSuggestion.action == "ban",
        )
    )
    pending = result.scalars().all()

    helper = get_helper_client()
    allowlist = await load_allowlist(db)
    now = datetime.now(timezone.utc)
    applied = 0
    skipped = 0

    for suggestion in pending:
        target = suggestion.target.strip()
        if "/" not in target and is_allowlisted(target, allowlist):
            skipped += 1
            continue
        try:
            await helper.ban_ip(target)
            suggestion.status = "approved"
            suggestion.reviewed_by = current_user.id
            suggestion.reviewed_at = now
            await _audit(db, current_user.id, "approve_suggestion", suggestion)
            applied += 1
        except PrivilegedHelperError as e:
            logger.warning("approve-all-bans: failed to ban %s: %s", target, e.message)

    db.add(AuditLog(
        user_id=current_user.id,
        action="approve_all_ban_suggestions",
        resource_type="ban_suggestion",
        resource_id="*",
        details=json.dumps({"applied": applied, "skipped_allowlisted": skipped}),
    ))
    await db.commit()
    return await list_suggestions(request, current_user=current_user, db=db)


@router.post("/suggestions/reject-all")
async def reject_all_pending(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark every pending suggestion rejected. Useful for clearing backlog."""
    from sqlalchemy import update

    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(BanSuggestion)
        .where(BanSuggestion.status == "pending")
        .values(status="rejected", reviewed_by=current_user.id, reviewed_at=now)
    )
    db.add(AuditLog(
        user_id=current_user.id,
        action="reject_all_suggestions",
        resource_type="ban_suggestion",
        resource_id="*",
        details=json.dumps({"count": result.rowcount or 0}),
    ))
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
        SETTING_AGENT_AUTO_BAN_ENABLED,
        SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE,
    )
    result = await db.execute(select(AppSetting).where(AppSetting.key.in_(keys)))
    rows = {r.key: r.value for r in result.scalars().all()}
    try:
        threshold = int(rows.get(SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE, "") or DEFAULT_AUTO_BAN_MIN_CONFIDENCE)
    except ValueError:
        threshold = DEFAULT_AUTO_BAN_MIN_CONFIDENCE
    return {
        "enabled": rows.get(SETTING_AGENT_ENABLED, "false").lower() in ("1", "true", "yes"),
        "interval_min": int(rows.get(SETTING_AGENT_INTERVAL_MIN, "10") or 10),
        "today_cost_usd": float(rows.get(SETTING_AGENT_DAILY_COST_USD, "0") or 0),
        "today_cost_date": rows.get(SETTING_AGENT_DAILY_COST_DATE, ""),
        "auto_ban_enabled": rows.get(SETTING_AGENT_AUTO_BAN_ENABLED, "false").lower() in ("1", "true", "yes"),
        "auto_ban_min_confidence": max(0, min(100, threshold)),
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
    auto_ban_enabled: str = Form("false"),
    auto_ban_min_confidence: int = Form(DEFAULT_AUTO_BAN_MIN_CONFIDENCE),
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if interval_min < 1 or interval_min > 1440:
        raise HTTPException(400, "interval_min must be between 1 and 1440")
    if auto_ban_min_confidence < 0 or auto_ban_min_confidence > 100:
        raise HTTPException(400, "auto_ban_min_confidence must be between 0 and 100")
    enabled_value = "true" if enabled.lower() in ("1", "true", "yes", "on") else "false"
    auto_ban_enabled_value = "true" if auto_ban_enabled.lower() in ("1", "true", "yes", "on") else "false"

    for key, value in (
        (SETTING_AGENT_ENABLED, enabled_value),
        (SETTING_AGENT_INTERVAL_MIN, str(interval_min)),
        (SETTING_AGENT_AUTO_BAN_ENABLED, auto_ban_enabled_value),
        (SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE, str(auto_ban_min_confidence)),
    ):
        row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
        if row:
            row.value = value
        else:
            db.add(AppSetting(key=key, value=value))
    await db.commit()
    return await get_agent_settings(request, current_user=current_user, db=db)
