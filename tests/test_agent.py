"""Tests for the log-triage agent."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.database import AppSetting, BanSuggestion, LogAgentRun
from app.services import log_agent
from app.services.llm_client import IPSummary, Suggestion, TokenUsage


# ── Pre-filter (pure function) ───────────────────────────────────────────────


def _entry(ip: str, service: str = "postfix", raw: str | None = None) -> dict:
    return {"src_ip": ip, "service": service, "raw": raw or f"sample line for {ip}"}


def test_prefilter_drops_allowlisted_ips():
    entries = [_entry("1.2.3.4")] * 5 + [_entry("10.0.0.5")] * 5
    summaries = log_agent.prefilter_entries(
        entries,
        allowlist=["10.0.0.0/8"],
        already_banned=set(),
        max_ips=10,
    )
    targets = {s.ip for s in summaries}
    assert "1.2.3.4" in targets
    assert "10.0.0.5" not in targets


def test_prefilter_drops_already_banned_ips():
    entries = [_entry("9.9.9.9")] * 4 + [_entry("8.8.8.8")] * 4
    summaries = log_agent.prefilter_entries(
        entries,
        allowlist=[],
        already_banned={"9.9.9.9"},
        max_ips=10,
    )
    targets = {s.ip for s in summaries}
    assert "9.9.9.9" not in targets
    assert "8.8.8.8" in targets


def test_prefilter_min_events_threshold():
    # 1.1.1.1 has only 2 events (< MIN_EVENTS_FOR_TRIAGE=3) → dropped.
    entries = [_entry("1.1.1.1")] * 2 + [_entry("2.2.2.2")] * 5
    summaries = log_agent.prefilter_entries(
        entries,
        allowlist=[],
        already_banned=set(),
        max_ips=10,
    )
    targets = {s.ip for s in summaries}
    assert "1.1.1.1" not in targets
    assert "2.2.2.2" in targets


def test_prefilter_skips_recently_triaged_targets():
    entries = [_entry("3.3.3.3")] * 5 + [_entry("4.4.4.4")] * 5
    summaries = log_agent.prefilter_entries(
        entries,
        allowlist=[],
        already_banned=set(),
        max_ips=10,
        recent_targets={"3.3.3.3"},
    )
    targets = {s.ip for s in summaries}
    assert "3.3.3.3" not in targets
    assert "4.4.4.4" in targets


def test_prefilter_caps_at_max_ips_and_sorts_by_count():
    entries = (
        [_entry("1.0.0.1")] * 10
        + [_entry("1.0.0.2")] * 7
        + [_entry("1.0.0.3")] * 5
        + [_entry("1.0.0.4")] * 4
    )
    summaries = log_agent.prefilter_entries(
        entries,
        allowlist=[],
        already_banned=set(),
        max_ips=2,
    )
    assert [s.ip for s in summaries] == ["1.0.0.1", "1.0.0.2"]


# ── Run-once: integration with mocked helper + LLM ───────────────────────────


@pytest.mark.asyncio
async def test_run_once_creates_suggestions_with_stub_llm(auth_client, db_engine):
    """Full agent iteration with the helper and LLM mocked."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client

    # Helper returns enough events for 1.2.3.4 to pass the 3-event threshold.
    mock_helper.read_logs.return_value = [
        {"ips": ["1.2.3.4"], "message": "Failed login", "service": "postfix"},
        {"ips": ["1.2.3.4"], "message": "Failed login", "service": "postfix"},
        {"ips": ["1.2.3.4"], "message": "Failed login", "service": "postfix"},
    ]
    mock_helper.list_banned_ips.return_value = []

    fake_suggestion = Suggestion(
        target="1.2.3.4",
        action="ban",
        confidence=85,
        reason="3 SMTP AUTH failures",
        evidence=["Failed login", "Failed login", "Failed login"],
    )

    async def fake_triage(grouped):
        return [fake_suggestion], TokenUsage(input_tokens=100, output_tokens=50), "test-model"

    # Bypass the api-key gate so the LLM path runs, and point log_agent at
    # the test in-memory DB so the suggestion shows up via the API.
    with patch("app.services.log_agent.async_session", factory), \
         patch("app.services.log_agent.triage_ips", side_effect=fake_triage), \
         patch.object(log_agent.settings, "anthropic_api_key", "test-key"):
        run = await log_agent.run_once(force=True)

    assert run.suggestions_created == 1
    assert run.input_tokens >= 100
    assert run.error is None

    # Suggestion is visible via the API.
    resp = await ac.get("/api/agent/suggestions")
    assert resp.status_code == 200
    assert b"1.2.3.4" in resp.content


@pytest.mark.asyncio
async def test_run_once_skipped_when_disabled(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    with patch("app.services.log_agent.async_session", factory):
        run = await log_agent.run_once(force=False)
    assert run.error == "agent disabled"
    assert run.suggestions_created == 0


@pytest.mark.asyncio
async def test_run_once_skipped_when_cost_cap_reached(auth_client, db_engine):
    """Daily cost cap is enforced before any LLM call."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    today = datetime.now(timezone.utc).date().isoformat()

    async with factory() as db:
        db.add(AppSetting(key=log_agent.SETTING_AGENT_DAILY_COST_USD, value="999.0"))
        db.add(AppSetting(key=log_agent.SETTING_AGENT_DAILY_COST_DATE, value=today))
        await db.commit()

    with patch("app.services.log_agent.async_session", factory), \
         patch.object(log_agent.settings, "anthropic_api_key", "test-key"):
        run = await log_agent.run_once(force=True)

    assert run.error and "cost cap" in run.error
    assert run.suggestions_created == 0


# ── Approve / reject routes ──────────────────────────────────────────────────


async def _create_pending(db, target: str, action: str = "ban") -> int:
    sug = BanSuggestion(target=target, action=action, confidence=80, reason="test")
    db.add(sug)
    await db.commit()
    await db.refresh(sug)
    return sug.id


@pytest.mark.asyncio
async def test_approve_ban_calls_helper(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client

    async with factory() as db:
        sid = await _create_pending(db, "5.6.7.8", action="ban")

    resp = await ac.post(f"/api/agent/suggestions/{sid}/approve")
    assert resp.status_code == 200
    mock_helper.ban_ip.assert_awaited_with("5.6.7.8")

    async with factory() as db:
        row = await db.get(BanSuggestion, sid)
        assert row.status == "approved"
        assert row.reviewed_by is not None


@pytest.mark.asyncio
async def test_approve_allowlist_appends_to_setting(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, _ = auth_client

    async with factory() as db:
        sid = await _create_pending(db, "64.233.160.5", action="allowlist")

    resp = await ac.post(f"/api/agent/suggestions/{sid}/approve")
    assert resp.status_code == 200

    from app.api.logs import SETTING_BAN_ALLOWLIST
    async with factory() as db:
        row = (await db.execute(
            select(AppSetting).where(AppSetting.key == SETTING_BAN_ALLOWLIST)
        )).scalar_one_or_none()
        assert row is not None
        assert "64.233.160.5" in row.value


@pytest.mark.asyncio
async def test_approve_ban_rejected_when_target_allowlisted(auth_client, db_engine):
    """Defense-in-depth: don't ban an IP that's on the allowlist."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from app.api.logs import SETTING_BAN_ALLOWLIST
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client

    async with factory() as db:
        db.add(AppSetting(key=SETTING_BAN_ALLOWLIST, value="64.233.160.5"))
        sid = await _create_pending(db, "64.233.160.5", action="ban")
        await db.commit()

    resp = await ac.post(f"/api/agent/suggestions/{sid}/approve")
    assert resp.status_code == 403
    mock_helper.ban_ip.assert_not_awaited()


@pytest.mark.asyncio
async def test_reject_marks_status_without_helper_call(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client

    async with factory() as db:
        sid = await _create_pending(db, "9.9.9.9", action="ban")

    resp = await ac.post(f"/api/agent/suggestions/{sid}/reject")
    assert resp.status_code == 200
    mock_helper.ban_ip.assert_not_awaited()

    async with factory() as db:
        row = await db.get(BanSuggestion, sid)
        assert row.status == "rejected"


# ── Suggestion expiry ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_old_pending_suggestions_get_expired(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async with factory() as db:
        old = BanSuggestion(target="1.1.1.1", action="ban", confidence=70, reason="old")
        old.created_at = datetime.now(timezone.utc) - timedelta(days=10)
        fresh = BanSuggestion(target="2.2.2.2", action="ban", confidence=70, reason="fresh")
        db.add_all([old, fresh])
        await db.commit()
        old_id, fresh_id = old.id, fresh.id

    with patch("app.services.log_agent.async_session", factory), \
         patch.object(log_agent.settings, "anthropic_api_key", ""):
        # API key empty → run skips the LLM path, but expiry sweep still runs.
        await log_agent.run_once(force=True)

    async with factory() as db:
        assert (await db.get(BanSuggestion, old_id)).status == "expired"
        assert (await db.get(BanSuggestion, fresh_id)).status == "pending"


# ── Settings round-trip ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_settings_round_trip(auth_client):
    ac, _ = auth_client
    resp = await ac.post("/api/agent/settings", data={"enabled": "true", "interval_min": "15"})
    assert resp.status_code == 200
    assert b"checked" in resp.content
    assert b"15" in resp.content
