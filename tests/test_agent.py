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


def test_prefilter_drops_ufw_only_ips():
    """UFW already dropped these packets — no point asking the LLM."""
    entries = (
        [_entry("5.5.5.5", service="ufw")] * 10
        + [_entry("6.6.6.6", service="ufw")] * 4
        + [_entry("6.6.6.6", service="ssh")] * 1
    )
    summaries = log_agent.prefilter_entries(
        entries,
        allowlist=[],
        already_banned=set(),
        max_ips=10,
    )
    targets = {s.ip for s in summaries}
    assert "5.5.5.5" not in targets  # UFW-only — skipped
    assert "6.6.6.6" in targets       # mixed — kept (SSH is actually listening)


def test_prefilter_can_opt_out_of_ufw_only_skip():
    entries = [_entry("7.7.7.7", service="ufw")] * 5
    summaries = log_agent.prefilter_entries(
        entries,
        allowlist=[],
        already_banned=set(),
        max_ips=10,
        skip_ufw_only=False,
    )
    assert {s.ip for s in summaries} == {"7.7.7.7"}


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
    mock_helper.read_logs_with_marker.return_value = (
        [
            {"ips": ["1.2.3.4"], "message": "Failed login", "service": "postfix"},
            {"ips": ["1.2.3.4"], "message": "Failed login", "service": "postfix"},
            {"ips": ["1.2.3.4"], "message": "Failed login", "service": "postfix"},
        ],
        "tail-marker",
    )
    mock_helper.list_banned_ips.return_value = []

    fake_suggestion = Suggestion(
        target="1.2.3.4",
        action="ban",
        confidence=85,
        reason="3 SMTP AUTH failures",
        evidence=["Failed login", "Failed login", "Failed login"],
    )

    async def fake_triage(grouped):
        return [fake_suggestion], TokenUsage(input_tokens=100, output_tokens=50), "test-model", "end_turn"

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


async def _create_pending(db, target: str, action: str = "ban", *, confidence: int = 80) -> int:
    sug = BanSuggestion(target=target, action=action, confidence=confidence, reason="test")
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
async def test_reject_all_marks_every_pending_rejected(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, _ = auth_client

    async with factory() as db:
        await _create_pending(db, "10.10.10.1")
        await _create_pending(db, "10.10.10.2")
        await _create_pending(db, "10.10.10.3")

    resp = await ac.post("/api/agent/suggestions/reject-all")
    assert resp.status_code == 200

    async with factory() as db:
        rows = (await db.execute(
            select(BanSuggestion).where(BanSuggestion.status == "pending")
        )).scalars().all()
        assert rows == []
        rejected = (await db.execute(
            select(BanSuggestion).where(BanSuggestion.status == "rejected")
        )).scalars().all()
        assert len(rejected) == 3


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


# ── Auto-approval of high-confidence bans ────────────────────────────────────


async def _run_with_single_suggestion(
    db_engine, mock_helper, suggestion: Suggestion, *,
    settings_to_seed=None, log_entry_ip: str | None = None,
):
    """Helper: run the agent once with a single LLM suggestion injected.

    `log_entry_ip` can differ from `suggestion.target` to simulate the case
    where the prefilter passes IP X but the LLM responds about IP Y — useful
    for testing the auto-approval allowlist re-check independently of the
    prefilter's own allowlist drop.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    if settings_to_seed:
        async with factory() as db:
            for key, value in settings_to_seed.items():
                db.add(AppSetting(key=key, value=value))
            await db.commit()

    async def fake_triage(grouped):
        return [suggestion], TokenUsage(input_tokens=10, output_tokens=5), "test-model", "end_turn"

    ip = log_entry_ip or suggestion.target
    mock_helper.read_logs_with_marker.return_value = (
        [
            {"ips": [ip], "message": "Failed login", "service": "postfix"},
            {"ips": [ip], "message": "Failed login", "service": "postfix"},
            {"ips": [ip], "message": "Failed login", "service": "postfix"},
        ],
        "tail-marker",
    )
    mock_helper.list_banned_ips.return_value = []

    with patch("app.services.log_agent.async_session", factory), \
         patch("app.services.log_agent.triage_ips", side_effect=fake_triage), \
         patch.object(log_agent.settings, "anthropic_api_key", "test-key"):
        run = await log_agent.run_once(force=True)
    return run, factory


@pytest.mark.asyncio
async def test_auto_approve_applies_high_confidence_ban(auth_client, db_engine):
    """Enabled + confidence >= threshold → helper.ban_ip called and status=approved."""
    sug = Suggestion(target="6.6.6.6", action="ban", confidence=90, reason="brute-force")
    ac, mock_helper = auth_client
    run, factory = await _run_with_single_suggestion(
        db_engine,
        mock_helper,
        sug,
        settings_to_seed={
            log_agent.SETTING_AGENT_AUTO_BAN_ENABLED: "true",
            log_agent.SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE: "80",
        },
    )

    mock_helper.ban_ip.assert_awaited_with("6.6.6.6")
    assert run.suggestions_created == 1
    async with factory() as db:
        row = (await db.execute(
            select(BanSuggestion).where(BanSuggestion.target == "6.6.6.6")
        )).scalar_one()
        assert row.status == "approved"
        assert row.reviewed_by is None
        assert row.reviewed_at is not None


@pytest.mark.asyncio
async def test_auto_approve_skips_low_confidence(auth_client, db_engine):
    """Confidence below the threshold leaves the suggestion pending."""
    sug = Suggestion(target="7.7.7.7", action="ban", confidence=75, reason="maybe")
    ac, mock_helper = auth_client
    run, factory = await _run_with_single_suggestion(
        db_engine,
        mock_helper,
        sug,
        settings_to_seed={
            log_agent.SETTING_AGENT_AUTO_BAN_ENABLED: "true",
            log_agent.SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE: "80",
        },
    )

    mock_helper.ban_ip.assert_not_awaited()
    async with factory() as db:
        row = (await db.execute(
            select(BanSuggestion).where(BanSuggestion.target == "7.7.7.7")
        )).scalar_one()
        assert row.status == "pending"


@pytest.mark.asyncio
async def test_auto_approve_never_bans_allowlisted_target(auth_client, db_engine):
    """Defense-in-depth: even if confidence clears the threshold, allowlisted IPs are never auto-banned."""
    from app.api.logs import SETTING_BAN_ALLOWLIST
    sug = Suggestion(target="64.233.160.99", action="ban", confidence=95, reason="false-positive")
    ac, mock_helper = auth_client
    # Log entries come from a non-allowlisted IP so the prefilter passes
    # something to the LLM; the mocked LLM then "responds" about the
    # allowlisted target — exercising the auto-approval re-check.
    run, factory = await _run_with_single_suggestion(
        db_engine,
        mock_helper,
        sug,
        log_entry_ip="1.2.3.4",
        settings_to_seed={
            log_agent.SETTING_AGENT_AUTO_BAN_ENABLED: "true",
            log_agent.SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE: "80",
            SETTING_BAN_ALLOWLIST: "64.233.160.0/19",
        },
    )

    mock_helper.ban_ip.assert_not_awaited()
    async with factory() as db:
        row = (await db.execute(
            select(BanSuggestion).where(BanSuggestion.target == "64.233.160.99")
        )).scalar_one()
        assert row.status == "pending"


@pytest.mark.asyncio
async def test_auto_approve_disabled_by_default(auth_client, db_engine):
    """No auto-ban settings present → all suggestions remain pending."""
    sug = Suggestion(target="8.8.8.8", action="ban", confidence=99, reason="obvious")
    ac, mock_helper = auth_client
    run, factory = await _run_with_single_suggestion(db_engine, mock_helper, sug)

    mock_helper.ban_ip.assert_not_awaited()
    async with factory() as db:
        row = (await db.execute(
            select(BanSuggestion).where(BanSuggestion.target == "8.8.8.8")
        )).scalar_one()
        assert row.status == "pending"


@pytest.mark.asyncio
async def test_auto_approve_does_not_apply_to_allowlist_action(auth_client, db_engine):
    """Auto-approve only applies to ban actions; allowlist suggestions still need a human."""
    sug = Suggestion(target="35.0.0.5", action="allowlist", confidence=95, reason="google")
    ac, mock_helper = auth_client
    run, factory = await _run_with_single_suggestion(
        db_engine,
        mock_helper,
        sug,
        settings_to_seed={
            log_agent.SETTING_AGENT_AUTO_BAN_ENABLED: "true",
            log_agent.SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE: "80",
        },
    )

    mock_helper.ban_ip.assert_not_awaited()
    async with factory() as db:
        row = (await db.execute(
            select(BanSuggestion).where(BanSuggestion.target == "35.0.0.5")
        )).scalar_one()
        assert row.status == "pending"


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


# ── History-based confidence boost ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_confidence_boosted_for_repeat_offender(auth_client, db_engine):
    """IP with 2 prior expired suggestions gets +20% confidence boost."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client

    # Seed 2 prior expired ban suggestions for the attacker IP.
    async with factory() as db:
        for _ in range(2):
            s = BanSuggestion(
                target="5.5.5.5", action="ban", confidence=70, reason="prior",
                status="expired",
            )
            s.created_at = datetime.now(timezone.utc) - timedelta(days=30)
            db.add(s)
        await db.commit()

    mock_helper.read_logs_with_marker.return_value = (
        [{"ips": ["5.5.5.5"], "message": "SSH brute", "service": "postfix"}] * 3,
        "marker",
    )
    mock_helper.list_banned_ips.return_value = []

    captured: list = []

    async def fake_triage(grouped):
        captured.extend(grouped)
        sug = Suggestion(target="5.5.5.5", action="ban", confidence=70, reason="ssh brute")
        return [sug], TokenUsage(input_tokens=10, output_tokens=5), "test-model", "end_turn"

    with patch("app.services.log_agent.async_session", factory), \
         patch("app.services.log_agent.triage_ips", side_effect=fake_triage), \
         patch.object(log_agent.settings, "anthropic_api_key", "test-key"):
        await log_agent.run_once(force=True)

    # IPSummary sent to LLM should carry prior_ban_suggestions=2.
    assert len(captured) == 1
    assert captured[0].prior_ban_suggestions == 2

    # Stored suggestion should have boosted confidence (70 + 2*10 = 90).
    async with factory() as db:
        rows = (await db.execute(
            select(BanSuggestion).where(
                BanSuggestion.target == "5.5.5.5",
                BanSuggestion.status == "pending",
            )
        )).scalars().all()
        assert len(rows) == 1
        assert rows[0].confidence == 90


@pytest.mark.asyncio
async def test_confidence_boost_does_not_trigger_auto_ban(auth_client, db_engine):
    """The repeat-offender boost must not push a suggestion over the auto-ban bar.

    The boost is an operator-facing signal. Gating unattended firewall changes
    on it would mean an IP gets banned for having been suggested before rather
    than for what it did in the window under review.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client

    # 1 prior expired suggestion → +10 boost → 70+10 = 80 → would have met the
    # threshold of 80 under the old policy.
    async with factory() as db:
        prior = BanSuggestion(
            target="6.6.6.6", action="ban", confidence=70, reason="prior",
            status="expired",
        )
        prior.created_at = datetime.now(timezone.utc) - timedelta(days=10)
        db.add(prior)
        db.add(AppSetting(key=log_agent.SETTING_AGENT_AUTO_BAN_ENABLED, value="true"))
        db.add(AppSetting(key=log_agent.SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE, value="80"))
        await db.commit()

    mock_helper.read_logs_with_marker.return_value = (
        [{"ips": ["6.6.6.6"], "message": "SSH brute", "service": "postfix"}] * 3,
        "marker",
    )
    mock_helper.list_banned_ips.return_value = []

    async def fake_triage(grouped):
        sug = Suggestion(target="6.6.6.6", action="ban", confidence=70, reason="ssh brute")
        return [sug], TokenUsage(input_tokens=10, output_tokens=5), "test-model", "end_turn"

    with patch("app.services.log_agent.async_session", factory), \
         patch("app.services.log_agent.triage_ips", side_effect=fake_triage), \
         patch.object(log_agent.settings, "anthropic_api_key", "test-key"):
        await log_agent.run_once(force=True)

    mock_helper.ban_ip.assert_not_awaited()

    # It still lands for review, with the boosted confidence shown.
    async with factory() as db:
        row = (await db.execute(
            select(BanSuggestion).where(
                BanSuggestion.target == "6.6.6.6",
                BanSuggestion.status == "pending",
            )
        )).scalar_one()
        assert row.confidence == 80


@pytest.mark.asyncio
async def test_auto_ban_applies_when_evidence_and_confidence_both_clear(auth_client, db_engine):
    """A well-evidenced, high-confidence ban is still applied unattended."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client

    async with factory() as db:
        db.add(AppSetting(key=log_agent.SETTING_AGENT_AUTO_BAN_ENABLED, value="true"))
        db.add(AppSetting(key=log_agent.SETTING_AGENT_AUTO_BAN_MIN_CONFIDENCE, value="90"))
        await db.commit()

    mock_helper.read_logs_with_marker.return_value = (
        [{"ips": ["7.7.7.7"], "message": "SASL LOGIN failed", "service": "postfix"}] * 6,
        "marker",
    )
    mock_helper.list_banned_ips.return_value = []

    async def fake_triage(grouped):
        sug = Suggestion(target="7.7.7.7", action="ban", confidence=95, reason="smtp auth brute")
        return [sug], TokenUsage(input_tokens=10, output_tokens=5), "test-model", "end_turn"

    with patch("app.services.log_agent.async_session", factory), \
         patch("app.services.log_agent.triage_ips", side_effect=fake_triage), \
         patch.object(log_agent.settings, "anthropic_api_key", "test-key"):
        await log_agent.run_once(force=True)

    mock_helper.ban_ip.assert_awaited_with("7.7.7.7")


# ── Watermarks ───────────────────────────────────────────────────────────────


def _seed_log_source(mock_helper, ip="9.9.9.9", count=6, marker="new-marker"):
    mock_helper.read_logs_with_marker.return_value = (
        [{"ips": [ip], "message": "SASL LOGIN failed", "service": "postfix"}] * count,
        marker,
    )
    mock_helper.list_banned_ips.return_value = []


@pytest.mark.asyncio
async def test_watermarks_not_advanced_when_triage_fails(auth_client, db_engine):
    """A failed run must leave the log window unconsumed.

    This is the bug that silently discarded eight hours of logs every time the
    API call failed: the markers were committed at gather time, so the next run
    started after lines nothing had ever triaged.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client
    _seed_log_source(mock_helper)

    async def boom(grouped):
        raise RuntimeError("credit balance is too low")

    with patch("app.services.log_agent.async_session", factory), \
         patch("app.services.log_agent.triage_ips", side_effect=boom), \
         patch.object(log_agent.settings, "anthropic_api_key", "test-key"):
        run = await log_agent.run_once(force=True)

    assert "RuntimeError" in run.error
    async with factory() as db:
        marker = await log_agent._get_setting(
            db, log_agent.SETTING_MARKER_PREFIX + "mail_postfix"
        )
    assert marker is None, "watermark advanced despite the run failing"


@pytest.mark.asyncio
async def test_watermarks_advanced_on_success(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client
    _seed_log_source(mock_helper)

    async def fake_triage(grouped):
        sug = Suggestion(target="9.9.9.9", action="ban", confidence=95, reason="brute")
        return [sug], TokenUsage(input_tokens=10, output_tokens=5), "test-model", "end_turn"

    with patch("app.services.log_agent.async_session", factory), \
         patch("app.services.log_agent.triage_ips", side_effect=fake_triage), \
         patch.object(log_agent.settings, "anthropic_api_key", "test-key"):
        run = await log_agent.run_once(force=True)

    assert run.error is None
    async with factory() as db:
        marker = await log_agent._get_setting(
            db, log_agent.SETTING_MARKER_PREFIX + "mail_postfix"
        )
    assert marker == "new-marker"


@pytest.mark.asyncio
async def test_truncated_output_is_recorded_on_the_run(auth_client, db_engine):
    """A run cut short at max_tokens must not look like a quiet one."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client
    _seed_log_source(mock_helper)

    async def fake_triage(grouped):
        return [], TokenUsage(input_tokens=10, output_tokens=5), "test-model", "max_tokens"

    with patch("app.services.log_agent.async_session", factory), \
         patch("app.services.log_agent.triage_ips", side_effect=fake_triage), \
         patch.object(log_agent.settings, "anthropic_api_key", "test-key"):
        run = await log_agent.run_once(force=True)

    assert "truncated" in run.error
    # Truncation is a failure, so the window is not consumed either.
    async with factory() as db:
        marker = await log_agent._get_setting(
            db, log_agent.SETTING_MARKER_PREFIX + "mail_postfix"
        )
    assert marker is None


@pytest.mark.asyncio
async def test_concurrent_run_is_refused(auth_client, db_engine):
    """The second caller is turned away rather than double-consuming the window."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client
    _seed_log_source(mock_helper)

    with patch("app.services.log_agent.async_session", factory):
        await log_agent._run_lock.acquire()
        try:
            run = await log_agent.run_once(force=True)
        finally:
            log_agent._run_lock.release()

    assert run.error == "another run is already in progress"
    mock_helper.read_logs_with_marker.assert_not_awaited()


# ── Auto-ban policy (pure) ───────────────────────────────────────────────────


def _summary(ip="1.2.3.4", events=10, services=("postfix",)):
    return IPSummary(
        ip=ip,
        total_events=events,
        services_touched=list(services),
        time_range="a → b",
        sample_lines=["evidence"],
    )


def _ban(ip="1.2.3.4", confidence=95):
    return Suggestion(target=ip, action="ban", confidence=confidence, reason="r")


@pytest.mark.parametrize(
    "suggestion, summary, base_conf, allowlist, expected",
    [
        (_ban(), _summary(), 95, [], True),
        # Thin evidence: a couple of stray failures is not an unattended ban.
        (_ban(), _summary(events=3), 95, [], False),
        # UFW-only traffic was already dropped at a closed port.
        (_ban(), _summary(services=("ufw",)), 95, [], False),
        # spamd is content scanning, not an authentication surface.
        (_ban(), _summary(services=("spamd",)), 95, [], False),
        # Confidence still applies, as a secondary filter.
        (_ban(confidence=95), _summary(), 60, [], False),
        # Allowlisted targets never get banned, however strong the evidence.
        (_ban(), _summary(), 95, ["1.2.3.4"], False),
        # CIDR ranges are too blunt to apply without a human.
        (_ban(ip="10.0.0.0/8"), _summary(ip="10.0.0.0/8"), 95, [], False),
        # No aggregation backing the target — not from this batch.
        (_ban(), None, 95, [], False),
        # Non-ban actions are never auto-applied.
        (Suggestion(target="1.2.3.4", action="allowlist", confidence=99, reason="r"),
         _summary(), 99, [], False),
    ],
)
def test_qualifies_for_auto_ban(suggestion, summary, base_conf, allowlist, expected):
    allowed, reason = log_agent.qualifies_for_auto_ban(
        suggestion, summary, base_conf, threshold=90, allowlist=allowlist
    )
    assert allowed is expected, reason


# ── Approve-all-bans ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_approve_all_bans_applies_each_and_skips_allowlisted(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from app.api.logs import SETTING_BAN_ALLOWLIST
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, mock_helper = auth_client

    async with factory() as db:
        db.add(AppSetting(key=SETTING_BAN_ALLOWLIST, value="64.233.160.0/19"))
        ban1 = await _create_pending(db, "10.20.30.40", action="ban")
        ban2 = await _create_pending(db, "10.20.30.41", action="ban")
        safe = await _create_pending(db, "64.233.160.5", action="ban")  # allowlisted
        al = await _create_pending(db, "35.0.0.5", action="allowlist")  # not a ban
        await db.commit()

    resp = await ac.post("/api/agent/suggestions/approve-all-bans")
    assert resp.status_code == 200

    mock_helper.ban_ip.assert_any_await("10.20.30.40")
    mock_helper.ban_ip.assert_any_await("10.20.30.41")
    # allowlisted IP must never be banned
    for call in mock_helper.ban_ip.await_args_list:
        assert call.args[0] != "64.233.160.5"

    async with factory() as db:
        assert (await db.get(BanSuggestion, ban1)).status == "approved"
        assert (await db.get(BanSuggestion, ban2)).status == "approved"
        # allowlisted → still pending (skipped)
        assert (await db.get(BanSuggestion, safe)).status == "pending"
        # allowlist-action suggestion → untouched (approve-all-bans only touches ban action)
        assert (await db.get(BanSuggestion, al)).status == "pending"


# ── Settings round-trip ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_settings_round_trip(auth_client):
    ac, _ = auth_client
    resp = await ac.post("/api/agent/settings", data={"enabled": "true", "interval_min": "15"})
    assert resp.status_code == 200
    assert b"checked" in resp.content
    assert b"15" in resp.content


# ── Pending-list sort options ────────────────────────────────────────────────


def _rendered_order(html: str, targets: list[str]) -> list[str]:
    """Return targets ordered by where they appear in the rendered partial."""
    return sorted(targets, key=html.index)


async def _seed_sort_fixtures(factory):
    """Three suggestions whose network order and confidence order differ."""
    async with factory() as db:
        await _create_pending(db, "195.96.139.186", confidence=85)
        await _create_pending(db, "23.129.64.145", confidence=70)
        await _create_pending(db, "185.220.100.246", confidence=95)
    return ["195.96.139.186", "23.129.64.145", "185.220.100.246"]


@pytest.mark.asyncio
async def test_default_sort_is_numeric_network_order(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, _ = auth_client
    targets = await _seed_sort_fixtures(factory)

    resp = await ac.get("/api/agent/suggestions")
    assert resp.status_code == 200
    # Numeric, not lexicographic: a string sort would put 23.x last.
    assert _rendered_order(resp.text, targets) == [
        "23.129.64.145",
        "185.220.100.246",
        "195.96.139.186",
    ]


@pytest.mark.asyncio
async def test_sort_by_confidence_descending(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, _ = auth_client
    targets = await _seed_sort_fixtures(factory)

    resp = await ac.get("/api/agent/suggestions?sort=confidence")
    assert resp.status_code == 200
    assert _rendered_order(resp.text, targets) == [
        "185.220.100.246",
        "195.96.139.186",
        "23.129.64.145",
    ]


@pytest.mark.asyncio
async def test_unknown_sort_falls_back_to_default(auth_client, db_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, _ = auth_client
    targets = await _seed_sort_fixtures(factory)

    resp = await ac.get("/api/agent/suggestions?sort=; DROP TABLE")
    assert resp.status_code == 200
    assert _rendered_order(resp.text, targets) == [
        "23.129.64.145",
        "185.220.100.246",
        "195.96.139.186",
    ]


@pytest.mark.asyncio
async def test_sort_survives_a_reject(auth_client, db_engine):
    """The re-rendered list after an action must keep the chosen sort."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, _ = auth_client
    await _seed_sort_fixtures(factory)

    async with factory() as db:
        sid = await _create_pending(db, "8.8.4.4", confidence=10)

    resp = await ac.post(f"/api/agent/suggestions/{sid}/reject?sort=confidence")
    assert resp.status_code == 200
    remaining = ["195.96.139.186", "23.129.64.145", "185.220.100.246"]
    assert _rendered_order(resp.text, remaining) == [
        "185.220.100.246",
        "195.96.139.186",
        "23.129.64.145",
    ]


@pytest.mark.asyncio
async def test_poll_url_in_partial_carries_the_sort(auth_client, db_engine):
    """Regression guard: the 30s refresh must not reset the sort to default."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    ac, _ = auth_client
    await _seed_sort_fixtures(factory)

    resp = await ac.get("/api/agent/suggestions?sort=oldest")
    assert 'hx-get="/api/agent/suggestions?sort=oldest"' in resp.text


def test_network_key_orders_numerically_and_tolerates_junk():
    from app.api.agent import _network_key

    targets = ["195.96.139.9", "23.129.64.145", "195.96.139.86", "not-an-ip"]
    assert sorted(targets, key=_network_key) == [
        "23.129.64.145",
        "195.96.139.9",
        "195.96.139.86",
        "not-an-ip",
    ]
    # The two things a plain string sort gets wrong, and the reason this key
    # exists: it puts 23.x last (since "2" > "1") and .86 before .9 (since
    # "8" < "9"). Junk sorts last either way.
    assert sorted(targets) == [
        "195.96.139.86",
        "195.96.139.9",
        "23.129.64.145",
        "not-an-ip",
    ]

