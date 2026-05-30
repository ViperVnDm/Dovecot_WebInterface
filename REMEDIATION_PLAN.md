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
- **Phase A ✅ COMPLETE.**
- **Last completed:** Step 2 — Mail Queue actions wired (the headline 501 bug).
- **Next up:** Step 3 — trust the reverse proxy for client IP (Phase B).
- **Last save point commit:** `plan(step2): wire Mail Queue action routes`.

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

- [ ] **Step 3 — Trust the reverse proxy for client IP (#3)**
  - Files: `systemd/dovecot-webadmin.service` (add `--proxy-headers
    --forwarded-allow-ips=127.0.0.1` to `ExecStart`), `README.md` (note the requirement)
  - Why: without it, `request.client.host` is always 127.0.0.1, so login rate-limiting is a
    single global bucket (brute-force + lockout-DoS) and every session IP logs as loopback.
  - Acceptance: behind nginx, `Session.ip_address` shows the real client IP; rate limit is
    per-IP. (Manual verify — note it in the commit; no unit test.)

- [ ] **Step 4 — Purge expired sessions (#4)**
  - Files: `app/services/alert_checker.py` or a small periodic task; `tests/test_auth.py`
  - Change: call `cleanup_expired_sessions()` on a timer (e.g. once/hour piggybacked on an
    existing loop) and/or opportunistically on login.
  - Acceptance: a test inserts an expired session and asserts the cleanup deletes it.

- [ ] **Step 5 — Complete + view the audit log (#5)** _(splittable: 5a writes, 5b viewer)_
  - Files: `app/api/users.py`, `app/api/logs.py` (ban/unban), `app/api/alerts.py` (write
    `AuditLog`); new `/audit` route + `partials/audit_log.html` (read-only view)
  - Acceptance: creating/deleting a mail user, changing a password, and manual ban/unban each
    write an `AuditLog` row; `/audit` renders them. Tests cover the writes.

---

## Phase C — Efficiency on 1 CPU / 4 GB

- [ ] **Step 6 — Stop walking every mailbox just to count users (#6)**
  - Files: `privileged/server.py` (+ `app/core/permissions.py`, `app/api/partials.py`)
  - Change: add a lightweight `count_users` path that skips `_user_mail_size`; have
    `/partials/dashboard/stats` use it. Optionally cache mailbox sizes on a timer.
  - Acceptance: dashboard stats no longer trigger a recursive maildir walk; a test asserts
    the dashboard-stats path doesn't call the sizing routine.

- [ ] **Step 7 — Run blocking helper commands in an executor (#7)**
  - Files: `privileged/server.py` (`handle_client` → `loop.run_in_executor` for `cmd_*`)
  - Acceptance: a slow command no longer serializes unrelated concurrent helper calls.

- [ ] **Step 8 — Cache log stats (#8)**
  - Files: `privileged/server.py` (`cmd_get_log_stats`) — memoize today's counts for ~30–60s.
  - Acceptance: repeated `get_log_stats` within the window doesn't re-scan `mail.log`.

- [ ] **Step 9 — SQLite WAL + busy_timeout (#9)**
  - Files: `app/database.py` (engine `connect_args` / PRAGMA on connect)
  - Acceptance: `PRAGMA journal_mode` returns `wal`; concurrent writes don't raise
    "database is locked" under a smoke test.

---

## Phase D — UI consistency & cross-page state (your original concern)

- [ ] **Step 10 — Persist UI state across pages (#10)**
  - Files: `app/templates/base.html`
  - Change: add `hx-boost="true"` so navigation is AJAX (state survives, faster loads);
    add Alpine `$persist` (or localStorage) for `sidebarOpen`.
  - Acceptance: collapse the sidebar, navigate to another page → it stays collapsed.

- [ ] **Step 11 — One reusable collapsible-card component (#11)**
  - Files: new `app/templates/partials/_card.html` (Jinja macro) or an Alpine pattern;
    apply to alerts settings + agent settings + other sections; `$persist` per-card open state.
  - Acceptance: every section card uses the same chrome; collapse state persists per card.

- [ ] **Step 12 — One name per page (#12)**
  - Files: route `title=` in `app/main.py`, page `<h1>`s, sidebar labels
  - Acceptance: sidebar label == browser tab title == H1 for every page.

- [ ] **Step 13 — Unify modals (#13)**
  - Files: user/alert/queue templates — single Alpine (or `<dialog>`) modal pattern; add focus trap.
  - Acceptance: all modals open/close/escape identically; no stray global keydown listeners.

---

## Phase E — Cleanup & deferred decisions

- [ ] **Step 14 — Implement or delete dead API stubs (#14)**
  - Files: `app/api/storage.py`, `app/api/logs.py::get_logs`, `/api/logs/ws`
  - Acceptance: no auth-protected route returns a hardcoded empty/501 placeholder.

- [ ] **Step 15 — Refresh stale docs + memory (#15)**
  - Files: `CLAUDE.md` "Known Quirks" (TemplateResponse migration is DONE on Starlette 1.0.0;
    `queue.py` already uses `pattern=` not `regex=`); memory `feedback_starlette_templateresponse.md`.
  - Acceptance: Known Quirks reflects reality; no contradicting memory.

- [ ] **Step E16 — DECISION: classify auth failures in the log viewer?** _(spun out of Step 1)_
  - Question: should `cmd_read_logs` mark "authentication failed" lines as `warning`
    (security-relevant) vs leave as `info` (avoid drowning the viewer in routine bot noise)?
  - If yes: update `detect_log_level()` + its test. This is a behavior change, hence isolated.

---

## Decision log
- 2026-05-29: auth-failure log highlighting deferred from Step 1 to Step E16 to keep the
  green-baseline step behavior-neutral.
