# CLAUDE.md — Dovecot Web Admin Console

Developer reference for Claude Code. Keep this file up to date when the architecture changes.

## Project Overview

FastAPI/Python web admin console for Dovecot + Postfix mail servers. Uses HTMX for dynamic UI without a JS framework. All privileged system operations are delegated to a separate root-level daemon via a Unix socket.

## Stack

- **Backend:** FastAPI, SQLAlchemy (async), aiosqlite, pydantic-settings
- **Templates:** Jinja2 + HTMX, Tailwind CSS (CDN)
- **Auth:** Custom session tokens (bcrypt passwords, DB-backed sessions, HttpOnly cookies)
- **Background tasks:** asyncio tasks started in FastAPI lifespan (alert checker, storage collector, log-triage agent, expired-session cleanup)
- **Tests:** pytest + pytest-asyncio, httpx AsyncClient, in-memory SQLite, unittest.mock

## Key Architecture Decisions

### Privilege Separation
The web app (`www-data`) never runs system commands. `privileged/server.py` runs as root, listens on a Unix socket at `/run/dovecot-webadmin/helper.sock`, and exposes a small set of validated commands. `app/core/permissions.py` is the IPC client.

### Helper IPC Protocol
JSON over Unix socket. Each command is `{"cmd": "...", "params": {...}}`. The helper validates all inputs with strict regex before executing anything. Adding a new privileged operation requires: (1) adding the command handler in `privileged/server.py`, (2) adding the client method in `app/core/permissions.py`.

### HTMX Partials
Page sections are loaded and refreshed via HTMX. All partial renderers live in `app/api/partials.py`. Each page template in `app/templates/` uses `hx-get` to load its partials on mount and `hx-trigger="every 30s"` for auto-refresh where appropriate.

### Database
SQLite via SQLAlchemy async. Models are in `app/database.py`. No Alembic migrations — `init_db()` uses `create_all` (suitable for this app's scale). Key-value runtime settings (SMTP config, alert check interval, IP allowlist) are stored in the `app_settings` table. Each SQLite connection is opened in WAL mode with a 5s `busy_timeout` (`_apply_sqlite_pragmas` on the SQLAlchemy `connect` event) so the several background loops and request handlers don't collide with "database is locked".

### Alert System
- `app/services/alert_checker.py`: background loop, evaluates rules, enforces cooldowns, writes `AlertHistory`, sends email/webhook
- Rule types: `storage`, `queue_size`, `deferred_count`
- Operators: `gt`, `gte`, `lt`, `lte`, `eq`
- `get_all_settings(db=None)` accepts an optional session — pass a FastAPI-injected session in route handlers so tests can use the in-memory DB override
- `send_test_email(recipient, db)` sends a test message using the *saved* SMTP settings; exposed via `POST /api/alerts/settings/test` so admins can verify delivery from the Alerts page. The result partial (`partials/alerts_test_result.html`) auto-clears on success after 6s (Alpine `x-init`) but keeps the error (with the SMTP exception text) on screen on failure.

### Storage History
`storage_collector_loop()` takes a disk usage snapshot on startup then every hour. `StorageHistory` records are queried last 30 days (one point per calendar day) for the history chart.

### Audit Log
`app/core/audit.py` `record_audit(db, ...)` adds an `AuditLog` row (the caller commits, so it shares the transaction of the change it records). Called from user CRUD (`users.py`), manual IP ban/unban (`logs.py`), alert-rule create/update/delete/toggle (`alerts.py`), and agent suggestion approve/reject (`agent.py` / `log_agent.py`). Viewable read-only at `/audit` via `/partials/audit/entries` (outer-joins `AdminUser` for the username; `user_id=None` renders as "system"). The source IP is `request.client.host`, accurate only because uvicorn runs with `--proxy-headers --forwarded-allow-ips=127.0.0.1` behind nginx (set in the systemd unit).

### IP Banning
UFW-based (`ufw insert 1 deny from <target>`). Supports both individual IPv4 addresses and CIDR ranges (e.g., `10.0.0.0/8`). Validation in the helper: `_validate_ip_or_cidr()` checks format, octet ranges, prefix length (0-32), and rejects loopback/wildcard. `cmd_list_banned_ips()` parses both CIDR and plain IP entries from `ufw status` output.

**CIDR consolidation:** When banning a CIDR range, individual IPs that fall within that range are automatically unbanned from UFW. The same consolidation applies to the never-ban allowlist — adding a CIDR removes covered individual IPs from the list.

**Never-ban allowlist:** stored as comma-separated string in `app_settings` with key `ban_allowlist`. The `/partials/logs/entries` route strips IPs that are on the allowlist from the ban button rendering. `is_allowlisted()` in `app/api/logs.py` handles both exact IP and CIDR matching via Python's `ipaddress` module.

**Export:** `GET /api/logs/export` returns a plain text file (attachment) containing both the banned IPs/CIDRs and the never-ban allowlist entries for disaster recovery backup.

### Log Reading
`privileged/server.py` reads logs via:
- **Postfix/Dovecot/SpamAssassin:** Full `/var/log/mail.log` read + Python-side service filter (not `tail`, because `tail` misses sparse services)
- **Web interface:** `journalctl -u dovecot-webadmin -o short-iso -n <lines>`

Log level detection checks for a Python log prefix (`INFO:`, `WARNING:`, `ERROR:`) at the start of the message *before* falling back to keyword search — this avoids false positives from URLs like `?level=error` in access logs.

### Mail Storage Path
Dovecot is configured with `mail_location = maildir:~/Mail:INBOX=~/Mail/Inbox:LAYOUT=fs`. Mailbox sizes are computed by walking `~/Mail/` and counting files in `cur/` and `new/` subdirectories only (not index files). Controlled by `USER_MAIL_SUBDIR` env var in the helper (default: `Mail`). Walking maildirs is expensive, so only `list_users` / `mailbox_sizes` do it — the dashboard user-count card uses the lightweight `count_users` command (group membership only, no filesystem walk).

## Common Tasks

### Adding a new API endpoint
1. Add route to the appropriate file in `app/api/`
2. If it needs the DB: add `db: AsyncSession = Depends(get_db)` parameter
3. If it needs the helper: call `helper = get_helper_client()` (function, not dependency)
4. If it needs auth: add `current_user: AdminUser = Depends(get_current_user)`

### Adding a new privileged helper command
1. In `privileged/server.py`: write `async def cmd_<name>(params)` and register it in the dispatch dict
2. Validate all string inputs with regex before passing to any shell command
3. In `app/core/permissions.py`: add a method that calls `self._send_command("<name>", {...})`

### Running tests
```bash
pytest tests/ -v
```
Tests run fully offline — in-memory SQLite, mocked helper. `test_helper_logic.py` is skipped on Windows (uses Unix `grp`/`pwd` modules).

### Deploying to server
The live install at `/opt/dovecot-webadmin/` is a git clone (set up by `setup.sh`). Updates are one command:

```bash
sudo dovecot-webadmin-update
```

`update.sh` pulls from the same branch installed, conditionally re-runs `pip install` if `requirements.txt` changed, re-copies systemd unit files and `daemon-reload`s them if they changed, then restarts both services. It refuses to run if `/opt/dovecot-webadmin/` is dirty (local edits) — that prevents silent loss of hand-patched files.

If `/opt/dovecot-webadmin/` is a legacy copy-based install (no `.git`), `update.sh` exits with migration instructions — see README.md → "Migrating an existing copy-based install".

## Test Fixture Notes

`tests/conftest.py` sets `COOKIE_SECURE=false` and clears the settings `lru_cache` so the test HTTP client (plain HTTP) can receive and send session cookies.

`get_helper_client` is imported by name in each api module, so it must be patched at each usage site:
- `app.api.logs.get_helper_client`
- `app.api.partials.get_helper_client`
- `app.api.users.get_helper_client`
- `app.api.queue.get_helper_client`
- `app.api.agent.get_helper_client`

If a new module imports `get_helper_client`, add it to the patch list in `conftest.py`.

`get_all_settings()` in `alert_checker.py` opens its own DB session when called without a `db` argument. Route handlers that call it must pass their injected `db` session so the test DB override applies.

## Environment Variables

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | `change-me-in-production` | Must be set in production |
| `DEBUG` | `false` | Enables SQLAlchemy echo and FastAPI /docs |
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/admin.db` | |
| `SESSION_EXPIRE_HOURS` | `24` | |
| `SMTP_FROM` | *(empty)* | Must be a real domain address for email alerts to deliver |
| `SMTP_HOST` | `localhost` | |
| `SMTP_PORT` | `25` | |
| `COOKIE_SECURE` | `true` | Set `false` in dev/test (no HTTPS) |
| `LOGIN_RATE_LIMIT` | `5/minute` | slowapi rate limit string |
| `HELPER_SOCKET_PATH` | `/run/dovecot-webadmin/helper.sock` | |
| `MAIL_LOG_PATH` | `/var/log/mail.log` | |

Runtime settings (SMTP config, alert interval, IP allowlist) are stored in the `app_settings` DB table, not in `.env`.

## Known Quirks

- `bcrypt` must be pinned to `<4.0.0` (passlib compatibility)
- Starlette `TemplateResponse` calls all use the new `(request, name, {...})` form (Starlette 1.0.0 + Jinja2 3.1). Keep using it — the old `(name, {"request": ...})` form raises `TypeError: unhashable type: 'dict'`. (Migration completed 2026-05-30.)
- `asyncio.open_unix_connection` does not exist on Windows; the helper IPC client will fail on Windows (expected — the helper is Linux-only)
