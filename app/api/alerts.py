"""Alert rules API routes."""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.database import get_db, AdminUser, AlertRule, AppSetting
from app.services.alert_checker import (
    get_all_settings,
    SETTING_CHECK_INTERVAL,
    SETTING_SMTP_FROM,
    SETTING_SMTP_HOST,
    SETTING_SMTP_PORT,
)

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


async def _render_rules(request: Request, db: AsyncSession):
    result = await db.execute(select(AlertRule).order_by(AlertRule.created_at.desc()))
    rules = result.scalars().all()
    return templates.TemplateResponse(
        "partials/alerts_rules.html",
        {"request": request, "rules": rules},
    )


@router.post("/rules")
async def create_rule(
    request: Request,
    name: str = Form(...),
    rule_type: str = Form(...),
    threshold_operator: str = Form(...),
    threshold_value: float = Form(...),
    notification_type: str = Form(...),
    notification_target: str = Form(...),
    cooldown_minutes: int = Form(default=60),
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new alert rule."""
    rule = AlertRule(
        name=name,
        rule_type=rule_type,
        threshold_operator=threshold_operator,
        threshold_value=threshold_value,
        notification_type=notification_type,
        notification_target=notification_target,
        cooldown_minutes=cooldown_minutes,
    )
    db.add(rule)
    await db.commit()
    return await _render_rules(request, db)


@router.delete("/rules/{rule_id}")
async def delete_rule(
    request: Request,
    rule_id: int,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an alert rule."""
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule:
        await db.delete(rule)
        await db.commit()
    return await _render_rules(request, db)


@router.post("/rules/{rule_id}/toggle")
async def toggle_rule(
    request: Request,
    rule_id: int,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Toggle an alert rule on/off."""
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule:
        rule.is_enabled = not rule.is_enabled
        await db.commit()
    return await _render_rules(request, db)


@router.get("/settings")
async def get_alert_settings(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
):
    """Return alert settings partial."""
    cfg = await get_all_settings()
    return templates.TemplateResponse(
        "partials/alerts_settings.html",
        {"request": request, **cfg},
    )


@router.post("/settings")
async def update_alert_settings(
    request: Request,
    check_interval: int = Form(..., ge=1, le=1440),
    smtp_from: str = Form(default=""),
    smtp_host: str = Form(default="localhost"),
    smtp_port: int = Form(default=25, ge=1, le=65535),
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update alert settings."""
    updates = {
        SETTING_CHECK_INTERVAL: str(check_interval),
        SETTING_SMTP_FROM: smtp_from.strip(),
        SETTING_SMTP_HOST: smtp_host.strip(),
        SETTING_SMTP_PORT: str(smtp_port),
    }

    for key, value in updates.items():
        result = await db.execute(select(AppSetting).where(AppSetting.key == key))
        setting = result.scalar_one_or_none()
        if setting:
            setting.value = value
        else:
            db.add(AppSetting(key=key, value=value))

    await db.commit()
    return templates.TemplateResponse(
        "partials/alerts_settings.html",
        {
            "request": request,
            "check_interval": check_interval,
            "smtp_from": smtp_from.strip(),
            "smtp_host": smtp_host.strip(),
            "smtp_port": smtp_port,
            "saved": True,
        },
    )
