"""FastAPI application entry point."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exception_handlers import http_exception_handler as _default_http_exception_handler
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.database import init_db
from app.services.alert_checker import alert_checker_loop, storage_collector_loop
from app.services.log_agent import agent_loop

# Import routers
from app.api import auth, users, queue, logs, storage, partials, alerts, agent
from app.core.security import get_current_user, cleanup_expired_sessions_loop
from app.core.limiter import limiter
from app.core.middleware import (
    CSRFMiddleware,
    SecurityHeadersMiddleware,
    get_csrf_token,
)
from app.database import get_db, AdminUser

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    await init_db()
    checker_task = asyncio.create_task(alert_checker_loop())
    storage_task = asyncio.create_task(storage_collector_loop())
    agent_task = asyncio.create_task(agent_loop())
    cleanup_task = asyncio.create_task(cleanup_expired_sessions_loop())
    yield
    checker_task.cancel()
    storage_task.cancel()
    agent_task.cancel()
    cleanup_task.cancel()
    for task in (checker_task, storage_task, agent_task, cleanup_task):
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title=settings.app_name,
    description="Web-based admin console for Dovecot/Postfix mail servers",
    version="0.1.0",
    lifespan=lifespan,
    # Disable interactive docs in production. They expose the full API
    # schema and would be reachable to anyone who can hit the server.
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(HTTPException)
async def unauthenticated_redirect(request: Request, exc: HTTPException):
    """Redirect unauthenticated *plain* browser navigations to the login page.

    Everything else keeps the JSON 401:

    - `/api/*` and `/partials/*` are consumed by HTMX and API clients, never
      typed into the address bar.
    - HTMX requests — including the `hx-boost`ed nav links, which is every
      in-app page link (see the `hx-boost="true"` on `<body>` in base.html) —
      travel over XHR, and XHR follows a 302 invisibly. The browser would swap
      the login page into the current layout while the URL bar still showed
      `/users`. The 401 instead reaches the `htmx:responseError` handler in
      base.html, which does a real top-level redirect.
    - `/login` must never redirect to `/login`: POST /login answers a bad
      password with a 401, and today it *returns* that response rather than
      raising, so it misses this handler by luck rather than by design.

    The requested path rides along as `?next=` so login lands the user where
    they were headed. `login()` re-validates it before honouring it — see
    `_safe_next()` in `app/api/auth.py`.
    """
    if (
        exc.status_code == status.HTTP_401_UNAUTHORIZED
        and not request.url.path.startswith(("/api/", "/partials/"))
        and request.url.path != "/login"
        and request.headers.get("hx-request") != "true"
    ):
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return RedirectResponse(
            url=f"/login?next={quote(target, safe='')}",
            status_code=302,
        )
    return await _default_http_exception_handler(request, exc)


# Security middleware (added in reverse order; CSRF runs before headers)
app.add_middleware(SecurityHeadersMiddleware, hsts=not settings.debug)
app.add_middleware(
    CSRFMiddleware,
    cookie_name=settings.csrf_cookie_name,
    secure=settings.cookie_secure,
)

# Static files
static_path = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_path), name="static")

# Templates (shared instance with CSRF helper installed)
from app.templates_setup import templates  # noqa: E402

# Include routers
app.include_router(auth.router, tags=["auth"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(queue.router, prefix="/api/queue", tags=["queue"])
app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
app.include_router(storage.router, prefix="/api/storage", tags=["storage"])
app.include_router(partials.router, prefix="/partials", tags=["partials"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
app.include_router(agent.router, prefix="/api/agent", tags=["agent"])


@app.get("/")
async def root(request: Request):
    """Redirect root to dashboard or login."""
    # Check if user is authenticated
    token = request.cookies.get(settings.session_cookie_name)
    if token:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/dashboard")
async def dashboard(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Main dashboard page."""
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"title": "Dashboard", "current_user": current_user},
    )


@app.get("/users")
async def users_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """User management page."""
    return templates.TemplateResponse(
        request,
        "users/list.html",
        {"title": "User Management", "current_user": current_user},
    )


@app.get("/queue")
async def queue_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Mail queue page."""
    return templates.TemplateResponse(
        request,
        "queue/index.html",
        {"title": "Mail Queue", "current_user": current_user},
    )


@app.get("/logs")
async def logs_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Logs viewer page."""
    return templates.TemplateResponse(
        request,
        "logs/index.html",
        {"title": "Logs & Stats", "current_user": current_user},
    )


@app.get("/firewall")
async def firewall_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Banned IPs and the never-ban allowlist."""
    return templates.TemplateResponse(
        request,
        "firewall/index.html",
        {"title": "Firewall", "current_user": current_user},
    )


@app.get("/storage")
async def storage_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Storage monitoring page."""
    return templates.TemplateResponse(
        request,
        "storage/index.html",
        {"title": "Storage", "current_user": current_user},
    )


@app.get("/alerts")
async def alerts_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Alerts configuration page."""
    return templates.TemplateResponse(
        request,
        "alerts/index.html",
        {"title": "Alerts", "current_user": current_user},
    )


@app.get("/agent")
async def agent_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Log-triage agent page."""
    return templates.TemplateResponse(
        request,
        "logs/agent.html",
        {"title": "Log Agent", "current_user": current_user},
    )


@app.get("/audit")
async def audit_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Audit log page."""
    return templates.TemplateResponse(
        request,
        "audit/index.html",
        {"title": "Audit Log", "current_user": current_user},
    )
