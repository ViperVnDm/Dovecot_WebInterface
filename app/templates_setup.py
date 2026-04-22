"""Shared Jinja2 templates instance with CSRF helper installed."""

from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.core.middleware import get_csrf_token


_TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=_TEMPLATES_DIR)
templates.env.globals["csrf_token"] = get_csrf_token
