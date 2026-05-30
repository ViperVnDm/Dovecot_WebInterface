# Remediation Plan — Dovecot Web Admin Console

_Created: 2026-05-29. This file is the durable, cross-session source of truth for the
review follow-up. It is designed to be paused after any step and resumed days later._

## How this plan works — READ FIRST

- **Save point = green tests + one git commit.** Every step is self-contained and ends
  at a save point. You can stop after any save point and lose nothing.
- **Work happens on the `remediation` branch**, never directly on `main`.
- **Source of truth for "what's done"** = the checkboxes below + `git log`. The numbers
  in parentheses (e.g. `#1`) map to the original review findings.
- Each step lists **Files**, the **Change**, and an **Acceptance** check so a fresh
  session (or a fresh pair of eyes) can verify it independently.
- Commit message convention: `plan(stepN): <summary>` so save points are greppable.

### ▶ To START (first time only)
```bash
cd /Users/nick/repos/Dovecot_WebInterface
git checkout -b remediation
git add -A && git commit -m "plan(step1): green-test baseline + de-drift log-level"
.venv/bin/python -m pytest tests/ -q     # must be green
```

### ⏸ To RESUME (any later session — even a brand-new Claude session)
1. `git log --oneline -10` → the newest `plan(stepN)` commit is your last save point.
2. Open this file → the first unchecked `[ ]` box is your next step.
3. `.venv/bin/python -m pytest tests/ -q` → should be green at every save point.
4. Tell Claude: **"Resume the remediation plan — next unchecked item in REMEDIATION_PLAN.md."**
   (A memory pointer makes Claude rediscover this file automatically.)
5. Work the one step, get tests green, commit `plan(stepN): …`, tick its box, stop or continue.

### Current status
- **Phases A + B + C ✅ COMPLETE. Phase D in progress.**
- **Note:** prod is ~1 GiB RAM / 1 CPU. SQLite flips delete→WAL on deploy. `hx-boost`
  is the one change not browser-verified here (trivially reverted: one body attribute).
- **🎉 ALL 16 STEPS COMPLETE (Phases A–E).**
- **Last completed:** Step 16 — auth failures classify as `warning` in the log viewer.
- **Next up:** test → merge `remediation` → `main` → deploy via `dovecot-webadmin-update`.
- **Last save point commit:** `plan(step16): classify auth failures as warning`.

---

## Phase A — Safety net (do these first; everything else leans on them)

- [x] **Step 1 — Green-test baseline + kill log-level drift** _(implemented this session)_
  - Files: `privileged/server.py`, `tests/test_helper_logic.py`
  - Change: extract `detect_log_level()` in the helper and call it from `cmd_read_logs`
    (pure refactor, no behavior change); fix the two stale tests
    (`_validate_ip("255.255.255.255")` is now correctly rejected as reserved;
    the auth-failure test asserted a behavior the code never had). The test now
    **imports** the real function instead of keeping a divergent copy.
  - Spun out: the question "should auth failures show as warning in the viewer?" → **Step E16**.
  - Acceptance: `.venv/bin/python -m pytest tests/ -q` is **green** (was 2 failing).

- [x] **Step 2 — Wire Mail Queue actions (#1)** ✅ _(done this session)_ — was the headline 501 bug
  - Files: `app/api/queue.py` (replaced the `501` stubs + `_render_queue_table` helper),
    `tests/conftest.py` (added `app.api.queue.get_helper_client` to the patch list),
    `tests/test_queue.py` (new, 8 tests)
  - Change: implemented `flush`, `{id}/flush`, `{id}/hold`, `{id}/release`, `DELETE {id}` by
    calling `get_helper_client()` and returning the refreshed `partials/queue_table.html`,
    mirroring `app/api/users.py`. `get_current_user` auth kept on each.
  - Acceptance: ✅ tests assert each route returns 200 and calls the matching helper method
    with the queue id; helper failure surfaces its error code; unauthenticated → 401.
  - Follow-up noted: on a *failed* action HTMX won't swap (non-2xx), so there's no visible
    error toast yet — consistent with the rest of the app; improve in Phase D (#13).

---

## Phase B — Security (highest real-world impact)

- [x] **Step 3 — Trust the reverse proxy for client IP (#3)** ✅ _(done this session)_
  - Files: `systemd/dovecot-webadmin.service` (add `--proxy-headers
    --forwarded-allow-ips=127.0.0.1` to `ExecStart`), `README.md` (note the requirement)
  - Why: without it, `request.client.host` is always 127.0.0.1, so login rate-limiting is a
    single global bucket (brute-force + lockout-DoS) and every session IP logs as loopback.
  - Acceptance: behind nginx, `Session.ip_address` shows the real client IP; rate limit is
    per-IP. (Manual verify — note it in the commit; no unit test.)

- [x] **Step 4 — Purge expired sessions (#4)** ✅ _(done this session)_ — hourly `cleanup_expired_sessions_loop`
  - Files: `app/services/alert_checker.py` or a small periodic task; `tests/test_auth.py`
  - Change: call `cleanup_expired_sessions()` on a timer (e.g. once/hour piggybacked on an
    existing loop) and/or opportunistically on login.
  - Acceptance: a test inserts an expired session and asserts the cleanup deletes it.

- [x] **Step 5 — Complete + view the audit log (#5)** ✅ _(done this session)_
  - Files: new `app/core/audit.py` (`record_audit` helper); audit writes in `app/api/users.py`
    (create/password/delete), `app/api/logs.py` (ban/unban), `app/api/alerts.py`
    (create/update/delete/toggle); viewer = `GET /audit` (main.py) +
    `/partials/audit/entries` (partials.py) + `templates/audit/index.html` +
    `templates/partials/audit_log.html`; sidebar link in base.html; `tests/test_audit.py` (7 tests).
  - Acceptance: ✅ each audited action writes a row (verified by reading it back through the
    viewer partial); `/audit` page loads; viewer is auth-protected. Source IP captured via
    `request.client.host` (now real, thanks to Step 3).

---

## Phase C — Efficiency on 1 CPU / 4 GB

- [x] **Step 6 — Stop walking every mailbox just to count users (#6)** ✅ _(done this session)_
  - Files: `privileged/server.py` (`_iter_mail_users` + `cmd_count_users`; list/mailbox
    refactored to share it), `app/core/permissions.py` (`count_users`),
    `app/api/partials.py` (dashboard uses it), `tests/test_dashboard.py`
  - Acceptance: ✅ test asserts dashboard stats call `count_users` and NOT `list_users`.
    Verified on prod: `count_users -> 3` (matches `getent group mail`), no maildir walk.

- [x] **Step 7 — Run blocking helper commands in an executor (#7)** ✅ _(done this session)_
  - Files: `privileged/server.py` (`handle_client` → `loop.run_in_executor`), `tests/test_helper_logic.py`
  - Acceptance: ✅ test drives `handle_client` with a fake reader/writer and asserts the
    command result is returned AND ran on a worker thread (not the event loop).

- [x] **Step 8 — Cache log stats (#8)** ✅ _(done this session)_
  - Files: `privileged/server.py` (`_compute_log_stats` + 60s cache in `cmd_get_log_stats`),
    `tests/test_helper_logic.py`
  - Acceptance: ✅ test asserts a second call within the TTL is served from cache (no rescan);
    cache invalidates on TTL lapse or day rollover; lock-guarded for the executor.

- [x] **Step 9 — SQLite WAL + busy_timeout (#9)** ✅ _(done this session)_
  - Files: `app/database.py` (`_apply_sqlite_pragmas` on the connect event:
    WAL + busy_timeout=5000 + synchronous=NORMAL), `tests/test_database.py`
  - Acceptance: ✅ test opens a file DB wired with the pragmas and asserts
    `journal_mode=wal`, `busy_timeout=5000`. Prod was `delete` before; deploy flips to WAL.

---

## Phase D — UI consistency & cross-page state (your original concern)

- [x] **Step 10 — Persist UI state across pages (#10)** ✅ _(done this session)_
  - Files: `app/templates/base.html`, `tests/test_pages.py` (new — 8-page smoke test)
  - Change: Alpine persist plugin + `sidebarOpen: $persist(...)`; `hx-boost="true"` on body
    (logout form `hx-boost="false"` so auth stays a plain POST); `htmx:responseError` now
    bounces 401s to `/login`.
  - Acceptance: ✅ page smoke tests green (server render). Cross-page collapse persistence +
    boosted nav need a browser to confirm (noted; hx-boost is one-attribute revertible).

- [x] **Step 11 — One reusable collapsible-card component (#11)** ✅ _(done this session)_
  - Files: new `app/templates/partials/_macros.html` (`collapsible_card`); applied to the
    Alerts "Notification Settings" and Agent "Agent Settings" cards.
  - Change: single source of truth for card chrome; per-card `$persist` open state; fixes the
    old double-`border-b` bug. Acceptance: ✅ both pages render (smoke test).
  - Follow-up: other static section cards can adopt the macro later — low priority.

- [x] **Step 12 — One name per page (#12)** ✅ _(done this session)_
  - Fixed: Logs (title→"Logs & Stats"), Storage (H1→"Storage"), Alerts (H1→"Alerts"),
    Agent (H1→"Log Agent"). Sidebar = tab title = H1 for all 8 pages now.

- [x] **Step 13 — Unify modals (#13)** ✅ _(done this session)_
  - The Alerts edit-modal used a stray global `keydown` listener; switched it to the Alpine
    `@keydown.escape.window` pattern the other modals use and removed the global listener.
  - Scoped down: a full `<dialog>`/focus-trap rewrite was deliberately NOT done (risky without
    a browser, and it'd add an Alpine focus-plugin dependency). Escape/close are consistent now.

---

## Phase E — Cleanup & deferred decisions

- [x] **Step 14 — Implement or delete dead API stubs (#14)** ✅ _(done this session)_
  - Removed the empty/501 placeholder routes + their now-unused Pydantic models and imports:
    `queue.py` GET `""`/`/stats`/`/{queue_id}`; `storage.py` `/mailboxes`/`/history`/`/alerts`;
    `logs.py` GET `""` (`get_logs`).
  - Kept (NOT placeholders): `storage.py /disk` (returns real data) and `logs.py /ws`
    (auth-gated + has a security test; streaming still a future enhancement).
  - Acceptance: ✅ full suite green; `import app.main` clean.

- [x] **Step 15 — Refresh stale docs + memory (#15)** ✅ _(done this session)_
  - `CLAUDE.md`: dropped the stale `regex=`/TemplateResponse quirks; documented the new
    subsystems (audit log, WAL pragmas, 4 background tasks, `count_users`); added queue+agent
    to the conftest patch list. Memory `feedback_starlette_templateresponse.md` marked complete.

- [x] **Step E16 — DECISION: classify auth failures in the log viewer?** ✅ _(done this session)_
  - **Decision: `warning`.** Security-relevant enough to stand out, but not `error` (failed
    SMTP/IMAP logins are routine bot traffic that would drown real errors). `detect_log_level()`
    + its test updated. One-line revert to `info` if preferred.

---

## Decision log
- 2026-05-29: auth-failure log highlighting deferred from Step 1 to Step E16 to keep the
  green-baseline step behavior-neutral.
