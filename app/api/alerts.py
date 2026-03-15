"""Alert rules API routes."""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.database import get_db, AdminUser, AlertRule

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
