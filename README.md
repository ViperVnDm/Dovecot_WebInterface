# Dovecot Web Admin Console

A web-based administration interface for Dovecot/Postfix mail servers. Built with FastAPI, HTMX, and Tailwind CSS.

## Features

- **User Management** — Create/delete system mail users, set passwords, view per-user mailbox sizes and message counts
- **Mail Queue** — View, flush, delete, hold, and release messages with auto-refresh; filter by queue type
- **Log Viewer** — Browse Postfix, Dovecot, SpamAssassin, and web interface logs; filter by level and service; ban IPs directly from log entries
- **IP Ban List** — Block IPs via UFW from the web UI; maintain a never-ban allowlist (supports CIDR ranges)
- **Storage Monitoring** — Disk usage overview, per-user mailbox sizes, 30-day usage history graph
- **Alerts** — Configurable threshold rules (storage, queue size, deferred count) with email and webhook notifications, cooldown enforcement, trigger history
- **Alert Settings** — Configure SMTP sender, host, port, and check interval from the web UI, with a "Send Test Email" button to verify delivery

## Architecture

```
┌─────────────────────┐    Unix socket    ┌──────────────────────┐
│  Web App (www-data) │ ◄────────────── ► │ Privileged Helper    │
│  FastAPI / uvicorn  │                   │ (root)               │
│  port 127.0.0.1:8000│                   │ privileged/server.py │
└─────────────────────┘                   └──────────────────────┘
         │                                          │
    SQLite DB                              System operations:
  (data/admin.db)                          - useradd / userdel
  - admin_users                            - passwd
  - sessions                               - UFW ban/unban
  - alert_rules                            - journalctl
  - alert_history                          - Postfix queue
  - app_settings                           - Maildir size reads
  - storage_history
```

The web app runs as `www-data` and never calls system commands directly. All privileged operations go through the helper daemon over a Unix socket with strict input validation and command allowlisting.

## Project Structure

```
Dovecot_WebInterface/
├── app/
│   ├── main.py              # FastAPI entry point, lifespan, route registration
│   ├── config.py            # Environment-based configuration (pydantic-settings)
│   ├── database.py          # SQLAlchemy models and async session management
│   ├── api/
│   │   ├── auth.py          # Login / logout endpoints
│   │   ├── users.py         # User management API
│   │   ├── queue.py         # Mail queue API
│   │   ├── logs.py          # Log viewer API, IP ban/unban, allowlist CRUD
│   │   ├── storage.py       # Storage monitoring API
│   │   ├── alerts.py        # Alert rules and settings API
│   │   └── partials.py      # HTMX partial renderers for all pages
│   ├── core/
│   │   ├── security.py      # Password hashing, session management, auth dependency
│   │   └── permissions.py   # IPC client that wraps all helper socket calls
│   ├── services/
│   │   └── alert_checker.py # Background tasks: alert evaluation, storage snapshots
│   └── templates/           # Jinja2 + HTMX templates (Tailwind CSS)
├── privileged/
│   └── server.py            # Root-level helper daemon (Unix socket server)
├── tests/
│   ├── conftest.py          # pytest fixtures: in-memory DB, mocked helper, auth client
│   ├── test_auth.py         # Login, logout, session, protected route tests
│   ├── test_alerts.py       # Alert rule CRUD, toggle, settings, history tests
│   ├── test_logs.py         # Allowlist parsing, CIDR matching, ban/unban, HTTP tests
│   └── test_helper_logic.py # Pure unit tests for validation functions (Unix only)
├── systemd/
│   ├── dovecot-webadmin.service         # Web app service (www-data)
│   └── dovecot-webadmin-helper.service  # Helper daemon service (root)
├── manage.py                # CLI: init-db, create-admin, change-password
├── setup.sh                 # Production installation script (git-clone-in-place)
├── update.sh                # In-place update: git pull + conditional pip/systemd + restart
├── requirements.txt
├── pyproject.toml           # pytest configuration
└── .env.example             # Configuration template
```

## Installation (Production)

### Prerequisites

- Ubuntu/Debian server running Dovecot and Postfix
- Python 3.10 or higher
- nginx (for HTTPS reverse proxy)
- UFW (for IP banning feature)
- Dovecot mail storage at `~/Mail/` (maildir format with `LAYOUT=fs`)

### 1. Clone and run the installer

```bash
git clone <repo-url> /tmp/dovecot-webadmin-src
cd /tmp/dovecot-webadmin-src
sudo ./setup.sh
```

The script will:
- `git clone` the repo into `/opt/dovecot-webadmin/` (so updates are a simple `git pull`)
- Create a Python virtualenv and install dependencies
- Generate a random `SECRET_KEY`
- Install and start both systemd services
- Install the `dovecot-webadmin-update` helper at `/usr/local/sbin/`
- Prompt for an initial admin username and password

The `/tmp/dovecot-webadmin-src` checkout is only used to invoke the installer — you can delete it afterwards. The live install lives at `/opt/dovecot-webadmin/`.

### 2. Configure `.env`

Edit `/opt/dovecot-webadmin/.env` after installation:

```ini
# Required — generate with: python3 -c "import secrets; print(secrets.token_urlsafe(32))"
SECRET_KEY=your-secret-key-here

# Alert notifications — must match your mail server's sending domain
SMTP_FROM=alerts@yourdomain.com
SMTP_HOST=localhost
SMTP_PORT=25

# Set to false only if running without HTTPS (not recommended for production)
# COOKIE_SECURE=true
```

### 3. Nginx reverse proxy (HTTPS required)

```nginx
server {
    listen 443 ssl;
    server_name mail.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> **Client IP behind the proxy:** the systemd unit launches uvicorn with
> `--proxy-headers --forwarded-allow-ips=127.0.0.1`, so it trusts the
> `X-Forwarded-For` set above **only** from the local nginx. This is what makes
> the real client IP available to the app — without it, login rate-limiting
> degrades to a single global bucket and session IPs are logged as `127.0.0.1`.
> If your proxy runs on a different host, set `--forwarded-allow-ips` to that
> host's address (never `*`).

### 4. Deploy updates

```bash
sudo dovecot-webadmin-update
```

That's it. The script:
- Refuses to run if `/opt/dovecot-webadmin/` has uncommitted local edits
- `git pull --ff-only` from the same branch you installed
- Re-runs `pip install` **only** when `requirements.txt` changed
- Refreshes `/etc/systemd/system/*.service` and reloads systemd **only** when the unit files changed
- Restarts both services and tails recent log entries

No-op updates (already at the latest commit) exit immediately. Equivalent direct invocation: `sudo /opt/dovecot-webadmin/update.sh`.

### Migrating an existing copy-based install

If you installed before `setup.sh` switched to clone-in-place, `/opt/dovecot-webadmin/` won't be a git checkout and `dovecot-webadmin-update` will refuse to run. One-time migration:

```bash
# Back up data + config
sudo cp /opt/dovecot-webadmin/.env /tmp/dwa.env.bak
sudo cp -r /opt/dovecot-webadmin/data /tmp/dwa-data.bak

# Stop services and remove the old install
sudo systemctl stop dovecot-webadmin dovecot-webadmin-helper
sudo rm -rf /opt/dovecot-webadmin

# Re-install (will git-clone this time) and restore data
sudo /tmp/dovecot-webadmin-src/setup.sh
sudo cp /tmp/dwa.env.bak /opt/dovecot-webadmin/.env
sudo cp -r /tmp/dwa-data.bak/* /opt/dovecot-webadmin/data/
sudo chown -R www-data:www-data /opt/dovecot-webadmin/data /opt/dovecot-webadmin/.env
sudo systemctl restart dovecot-webadmin-helper dovecot-webadmin
```

When `setup.sh` prompts for a new admin user during the re-install, pick any value — the restored `data/admin.db` will overwrite that account immediately afterwards.

## Configuration Reference

All settings are read from `/opt/dovecot-webadmin/.env` (or environment variables). Defaults shown.

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(required)* | Random secret for session signing — change in production |
| `DEBUG` | `false` | Enable debug logging and FastAPI docs |
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/admin.db` | SQLite database path |
| `SESSION_EXPIRE_HOURS` | `24` | Session lifetime |
| `SMTP_FROM` | *(empty)* | Alert sender address — must be set for email notifications |
| `SMTP_HOST` | `localhost` | SMTP relay host |
| `SMTP_PORT` | `25` | SMTP port |
| `COOKIE_SECURE` | `true` | Set `false` only when running without HTTPS |
| `LOGIN_RATE_LIMIT` | `5/minute` | Brute-force protection on `/login` |
| `HELPER_SOCKET_PATH` | `/run/dovecot-webadmin/helper.sock` | Unix socket for helper IPC |
| `MAIL_LOG_PATH` | `/var/log/mail.log` | Path to Postfix/Dovecot mail log |

Alert check interval and SMTP settings are also configurable at runtime from the Alerts → Settings page in the web UI and are stored in the database.

## Development Setup

```bash
git clone <repo-url>
cd Dovecot_WebInterface
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Initialize DB and create admin user
python manage.py init-db
python manage.py create-admin

# Run development server (no privileged helper — system operations will fail gracefully)
uvicorn app.main:app --reload
```

The app will be available at `http://localhost:8000`. Log in with the admin credentials you created.

> **Note:** Without the privileged helper running, operations that require system access (user creation/deletion, IP banning, reading live logs) will return errors. For full functionality, run on a Linux server with the helper daemon active.

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

Tests use an in-memory SQLite database and a mocked privileged helper — no running services required. Tests in `test_helper_logic.py` are skipped on Windows because the helper uses Unix-only modules (`grp`, `pwd`).

To run just a subset:

```bash
pytest tests/test_auth.py -v
pytest tests/test_logs.py -v
pytest tests/test_alerts.py -v
```

## Service Management

```bash
# Status
systemctl status dovecot-webadmin
systemctl status dovecot-webadmin-helper

# Restart after code changes
sudo systemctl restart dovecot-webadmin dovecot-webadmin-helper

# Logs
journalctl -u dovecot-webadmin -f
journalctl -u dovecot-webadmin-helper -f
```

## Security Notes

- The web app process (`www-data`) has no sudo access and cannot run system commands directly
- The helper daemon validates all inputs with strict regex before executing any system operation
- Reserved usernames (`root`, `postfix`, `dovecot`, etc.) cannot be created through the web UI
- IP banning validates address format and rejects loopback/wildcard addresses
- The never-ban allowlist protects your own IPs from accidental banning
- Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` (requires HTTPS in production)
- Login attempts are rate-limited to 5 per minute per IP

## Mail Storage Assumptions

The app assumes Dovecot is configured with:

```
mail_location = maildir:~/Mail:INBOX=~/Mail/Inbox:LAYOUT=fs
```

Mailbox sizes are computed by walking `~/Mail/` and counting files only in `cur/` and `new/` subdirectories (actual messages, not index files). If your layout differs, adjust `USER_MAIL_SUBDIR` in the helper environment.
