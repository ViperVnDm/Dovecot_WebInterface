"""Background log-triage agent.

Reads recent mail/auth/UFW logs, pre-filters per source IP, asks Claude
to triage the noisiest unknowns, and writes BanSuggestion rows to the DB
for a human to approve in the web UI. Modeled on alert_checker.py.

The agent never applies actions on its own — approval flows through
app/api/agent.py which calls the existing privileged helper.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import select, update

from app.api.logs import SETTING_BAN_ALLOWLIST, is_allowlisted, _parse_allowlist
from app.config import get_settings
from app.core.permissions import PrivilegedHelperError, get_helper_client
from app.database import AppSetting, BanSuggestion, LogAgentRun, async_session
from app.services.llm_client import IPSummary, Suggestion, TokenUsage, triage_ips

logger = logging.getLogger(__name__)
settings = get_settings()


SETTING_AGENT_ENABLED = "log_agent_enabled"
SETTING_AGENT_INTERVAL_MIN = "log_agent_interval_min"
SETTING_AGENT_DAILY_COST_USD = "log_agent_daily_cost_usd"
SETTING_AGENT_DAILY_COST_DATE = "log_agent_daily_cost_date"

DEFAULT_INTERVAL_MIN = 10
SUGGESTION_EXPIRY_DAYS = 7
MIN_EVENTS_FOR_TRIAGE = 3
LINES_PER_SOURCE = 1000  # cap when reading each log source


# ── Settings I/O ─────────────────────────────────────────────────────────────


async def _get_setting(db, key: str, default: str | None = None) -> str | None:
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    row = result.scalar_one_or_none()
    return row.value if row else default


async def _set_setting(db, key: str, value: str) -> None:
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    row = result.scalar_one_or_none()
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))


async def _is_enabled(db) -> bool:
    raw = await _get_setting(db, SETTING_AGENT_ENABLED, "false")
    return raw.lower() in ("1", "true", "yes")


async def _interval_min(db) -> int:
    raw = await _get_setting(db, SETTING_AGENT_INTERVAL_MIN, str(DEFAULT_INTERVAL_MIN))
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_INTERVAL_MIN


async def _today_cost(db) -> float:
    today = datetime.now(timezone.utc).date().isoformat()
    date_value = await _get_setting(db, SETTING_AGENT_DAILY_COST_DATE)
    if date_value != today:
        return 0.0
    raw = await _get_setting(db, SETTING_AGENT_DAILY_COST_USD, "0")
    try:
        return float(raw)
    except ValueError:
        return 0.0


async def _record_cost(db, additional_usd: float) -> None:
    today = datetime.now(timezone.utc).date().isoformat()
    date_value = await _get_setting(db, SETTING_AGENT_DAILY_COST_DATE)
    current = await _today_cost(db) if date_value == today else 0.0
    await _set_setting(db, SETTING_AGENT_DAILY_COST_DATE, today)
    await _set_setting(db, SETTING_AGENT_DAILY_COST_USD, f"{current + additional_usd:.6f}")


# ── Pre-filter ───────────────────────────────────────────────────────────────


def _extract_ip(entry: dict) -> str | None:
    ip = entry.get("src_ip")
    if ip:
        return ip
    ips = entry.get("ips") or []
    return ips[0] if ips else None


def prefilter_entries(
    raw_entries: list[dict],
    allowlist: list[str],
    already_banned: set[str],
    max_ips: int,
    min_events: int = MIN_EVENTS_FOR_TRIAGE,
) -> list[IPSummary]:
    """Group raw log entries by source IP and drop ones we already handle.

    Pure function so it can be unit-tested without the helper or DB.
    """
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for entry in raw_entries:
        ip = _extract_ip(entry)
        if not ip:
            continue
        if ip in already_banned:
            continue
        if is_allowlisted(ip, allowlist):
            continue
        by_ip[ip].append(entry)

    summaries: list[IPSummary] = []
    for ip, events in by_ip.items():
        if len(events) < min_events:
            continue
        services = sorted({e.get("service", "?") for e in events})
        sample_lines = [e.get("raw") or e.get("message") or "" for e in events[:5]]
        # Best-effort time range — first and last raw timestamps if present
        first = events[0].get("timestamp") or events[0].get("raw", "")[:32]
        last = events[-1].get("timestamp") or events[-1].get("raw", "")[:32]
        summaries.append(IPSummary(
            ip=ip,
            total_events=len(events),
            services_touched=services,
            time_range=f"{first} → {last}",
            sample_lines=sample_lines,
        ))

    summaries.sort(key=lambda s: s.total_events, reverse=True)
    return summaries[:max_ips]


# ── Suggestion persistence ───────────────────────────────────────────────────


async def _has_pending_suggestion(db, target: str) -> bool:
    result = await db.execute(
        select(BanSuggestion).where(
            BanSuggestion.target == target,
            BanSuggestion.status == "pending",
        ).limit(1)
    )
    return result.scalar_one_or_none() is not None


async def _expire_old_suggestions(db) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=SUGGESTION_EXPIRY_DAYS)
    result = await db.execute(
        update(BanSuggestion)
        .where(BanSuggestion.status == "pending")
        .where(BanSuggestion.created_at < cutoff)
        .values(status="expired")
    )
    return result.rowcount or 0


# ── Run orchestration ────────────────────────────────────────────────────────


async def _gather_log_entries() -> list[dict]:
    """Pull recent log entries from every source the agent watches."""
    helper = get_helper_client()
    all_entries: list[dict] = []

    for service in ("postfix", "dovecot", "spamd"):
        try:
            entries = await helper.read_logs(lines=LINES_PER_SOURCE, service=service)
            for e in entries:
                e.setdefault("service", service)
                # cmd_read_logs returns "ips" not "src_ip" — normalize.
                if "src_ip" not in e and e.get("ips"):
                    e["src_ip"] = e["ips"][0]
                e.setdefault("raw", e.get("message", ""))
            all_entries.extend(entries)
        except PrivilegedHelperError as exc:
            logger.warning("read_logs(%s) failed: %s", service, exc.message)

    try:
        all_entries.extend(await helper.read_auth_log(max_lines=LINES_PER_SOURCE))
    except PrivilegedHelperError as exc:
        logger.warning("read_auth_log failed: %s", exc.message)

    try:
        all_entries.extend(await helper.read_ufw_log(max_lines=LINES_PER_SOURCE))
    except PrivilegedHelperError as exc:
        logger.warning("read_ufw_log failed: %s", exc.message)

    return all_entries


async def run_once(force: bool = False) -> LogAgentRun:
    """Execute a single agent iteration. Returns the LogAgentRun row.

    force=True bypasses the enabled flag (for the "Run now" button) but still
    respects the daily cost cap and the missing-API-key guard.
    """
    started_at = datetime.now(timezone.utc)
    async with async_session() as db:
        enabled = await _is_enabled(db)
        cost_today = await _today_cost(db)
        await _expire_old_suggestions(db)
        await db.commit()

    cap = float(settings.log_agent_daily_cost_cap_usd)

    run = LogAgentRun(started_at=started_at)
    async with async_session() as db:
        db.add(run)
        await db.commit()
        await db.refresh(run)

    skip_reason: str | None = None
    if not force and not enabled:
        skip_reason = "agent disabled"
    elif cost_today >= cap:
        skip_reason = f"daily cost cap reached (${cost_today:.4f} >= ${cap:.4f})"
    elif not settings.anthropic_api_key:
        skip_reason = "ANTHROPIC_API_KEY not set"

    if skip_reason:
        async with async_session() as db:
            row = await db.get(LogAgentRun, run.id)
            row.finished_at = datetime.now(timezone.utc)
            row.error = skip_reason
            await db.commit()
            await db.refresh(row)
            logger.info("Agent run skipped: %s", skip_reason)
            return row

    helper = get_helper_client()

    # Gather + pre-filter
    raw_entries = await _gather_log_entries()
    async with async_session() as db:
        allowlist_raw = await _get_setting(db, SETTING_BAN_ALLOWLIST, "") or ""
        allowlist = _parse_allowlist(allowlist_raw)
    try:
        already_banned = set(await helper.list_banned_ips())
    except PrivilegedHelperError:
        already_banned = set()

    summaries = prefilter_entries(
        raw_entries,
        allowlist=allowlist,
        already_banned=already_banned,
        max_ips=int(settings.log_agent_max_ips_per_run),
    )

    suggestions: list[Suggestion] = []
    usage = TokenUsage()
    model = settings.log_agent_model
    error: str | None = None
    if summaries:
        try:
            suggestions, usage, model = await triage_ips(summaries)
        except Exception as exc:  # network / SDK / parse errors
            logger.exception("triage_ips failed")
            error = f"{type(exc).__name__}: {exc}"

    # Persist suggestions + run record + cost
    inserted = 0
    async with async_session() as db:
        for s in suggestions:
            if s.action == "ignore":
                continue
            if await _has_pending_suggestion(db, s.target):
                continue
            db.add(BanSuggestion(
                target=s.target,
                action=s.action,
                confidence=s.confidence,
                reason=s.reason,
                evidence=json.dumps(s.evidence),
                run_id=run.id,
            ))
            inserted += 1

        row = await db.get(LogAgentRun, run.id)
        row.finished_at = datetime.now(timezone.utc)
        row.lines_analyzed = len(raw_entries)
        row.suggestions_created = inserted
        row.model = model
        row.input_tokens = usage.input_tokens + usage.cache_creation_tokens + usage.cache_read_tokens
        row.output_tokens = usage.output_tokens
        row.cost_usd = usage.cost_usd
        row.error = error
        await _record_cost(db, usage.cost_usd)
        await db.commit()
        await db.refresh(row)
        logger.info(
            "Agent run %d done: lines=%d ips=%d suggestions=%d cost=$%.4f",
            row.id, row.lines_analyzed, len(summaries), inserted, row.cost_usd,
        )
        return row


async def agent_loop() -> None:
    """Long-running background task; sleeps interval_min between runs."""
    logger.info("Log-agent background task started")
    while True:
        async with async_session() as db:
            interval = await _interval_min(db)
        await asyncio.sleep(interval * 60)
        try:
            await run_once(force=False)
        except Exception:
            logger.exception("Unhandled error in agent loop")
