"""FastAPI application entry point."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import get_settings
from app.database import init_db

# Import routers
from app.api import auth, users, queue, logs, storage, partials, alerts
from app.core.security import get_current_user
from app.database import get_db, AdminUser

settings = get_settings()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    await init_db()
    yield
    # Shutdown (cleanup if needed)


app = FastAPI(
    title=settings.app_name,
    description="Web-based admin console for Dovecot/Postfix mail servers",
    version="0.1.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Static files
static_path = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_path), name="static")

# Templates
templates_path = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=templates_path)

# Include routers
app.include_router(auth.router, tags=["auth"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(queue.router, prefix="/api/queue", tags=["queue"])
app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
app.include_router(storage.router, prefix="/api/storage", tags=["storage"])
app.include_router(partials.router, prefix="/partials", tags=["partials"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])


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
        "dashboard.html",
        {"request": request, "title": "Dashboard", "current_user": current_user},
    )


@app.get("/users")
async def users_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """User management page."""
    return templates.TemplateResponse(
        "users/list.html",
        {"request": request, "title": "User Management", "current_user": current_user},
    )


@app.get("/queue")
async def queue_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Mail queue page."""
    return templates.TemplateResponse(
        "queue/index.html",
        {"request": request, "title": "Mail Queue", "current_user": current_user},
    )


@app.get("/logs")
async def logs_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Logs viewer page."""
    return templates.TemplateResponse(
        "logs/index.html",
        {"request": request, "title": "Mail Logs", "current_user": current_user},
    )


@app.get("/storage")
async def storage_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Storage monitoring page."""
    return templates.TemplateResponse(
        "storage/index.html",
        {"request": request, "title": "Storage", "current_user": current_user},
    )


@app.get("/alerts")
async def alerts_page(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Alerts configuration page."""
    return templates.TemplateResponse(
        "alerts/index.html",
        {"request": request, "title": "Alerts", "current_user": current_user},
    )
