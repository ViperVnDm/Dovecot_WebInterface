"""Alert rules API routes."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import record_audit
from app.core.security import get_current_user
from app.core.webhook import WebhookTargetError, validate_webhook_url
from app.database import get_db, AdminUser, AlertRule, AppSetting
from app.services.alert_checker import (
    get_all_settings,
    send_test_email,
    SETTING_CHECK_INTERVAL,
    SETTING_SMTP_FROM,
    SETTING_SMTP_HOST,
    SETTING_SMTP_PORT,
)
from app.templates_setup import templates


VALID_RULE_TYPES = frozenset({"storage", "queue_size", "deferred_count"})
VALID_OPERATORS = frozenset({"gt", "gte", "lt", "lte", "eq"})
VALID_NOTIFICATION_TYPES = frozenset({"email", "webhook"})


def _validate_email_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise HTTPException(400, "Notification target is required")
    if any(ch in target for ch in ("\r", "\n", "\x00")):
        raise HTTPException(400, "Notification target contains forbidden characters")
    if "@" not in target or len(target) > 254:
        raise HTTPException(400, "Invalid email address")
    return target


def _validate_webhook_target(target: str) -> str:
    """Validate a webhook URL: must be https, not localhost, not private/link-local.

    This is only the save-time gate — the same checks run again on every hop at
    delivery time, since DNS can change in between. See `app/core/webhook.py`.
    """
    try:
        return validate_webhook_url(target)
    except WebhookTargetError as exc:
        raise HTTPException(400, str(exc))


def _validate_rule_inputs(
    name: str,
    rule_type: str,
    threshold_operator: str,
    notification_type: str,
    notification_target: str,
) -> str:
    if not name or any(ch in name for ch in ("\r", "\n", "\x00")):
        raise HTTPException(400, "Invalid rule name")
    if rule_type not in VALID_RULE_TYPES:
        raise HTTPException(400, f"Invalid rule_type (must be one of {sorted(VALID_RULE_TYPES)})")
    if threshold_operator not in VALID_OPERATORS:
        raise HTTPException(400, f"Invalid operator (must be one of {sorted(VALID_OPERATORS)})")
    if notification_type not in VALID_NOTIFICATION_TYPES:
        raise HTTPException(
            400, f"Invalid notification_type (must be one of {sorted(VALID_NOTIFICATION_TYPES)})"
        )
    if notification_type == "email":
        return _validate_email_target(notification_target)
    return _validate_webhook_target(notification_target)


router = APIRouter()


async def _render_rules(request: Request, db: AsyncSession):
    result = await db.execute(select(AlertRule).order_by(AlertRule.created_at.desc()))
    rules = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "partials/alerts_rules.html",
        {"rules": rules},
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
    notification_target = _validate_rule_inputs(
        name, rule_type, threshold_operator, notification_type, notification_target
    )
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
    await db.flush()
    await record_audit(
        db, user_id=current_user.id, action="create_alert_rule",
        resource_type="alert_rule", resource_id=str(rule.id),
        details={"name": name, "rule_type": rule_type}, request=request,
    )
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
        await record_audit(
            db, user_id=current_user.id, action="delete_alert_rule",
            resource_type="alert_rule", resource_id=str(rule_id),
            details={"name": rule.name}, request=request,
        )
        await db.delete(rule)
        await db.commit()
    return await _render_rules(request, db)


@router.patch("/rules/{rule_id}")
async def update_rule(
    request: Request,
    rule_id: int,
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
    """Update an existing alert rule."""
    notification_target = _validate_rule_inputs(
        name, rule_type, threshold_operator, notification_type, notification_target
    )
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule:
        rule.name = name
        rule.rule_type = rule_type
        rule.threshold_operator = threshold_operator
        rule.threshold_value = threshold_value
        rule.notification_type = notification_type
        rule.notification_target = notification_target
        rule.cooldown_minutes = cooldown_minutes
        await record_audit(
            db, user_id=current_user.id, action="update_alert_rule",
            resource_type="alert_rule", resource_id=str(rule_id),
            details={"name": name}, request=request,
        )
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
        await record_audit(
            db, user_id=current_user.id, action="toggle_alert_rule",
            resource_type="alert_rule", resource_id=str(rule_id),
            details={"enabled": rule.is_enabled}, request=request,
        )
        await db.commit()
    return await _render_rules(request, db)


@router.get("/settings")
async def get_alert_settings(
    request: Request,
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return alert settings partial."""
    cfg = await get_all_settings(db)
    return templates.TemplateResponse(
        request,
        "partials/alerts_settings.html",
        {**cfg},
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
        request,
        "partials/alerts_settings.html",
        {
            "check_interval": check_interval,
            "smtp_from": smtp_from.strip(),
            "smtp_host": smtp_host.strip(),
            "smtp_port": smtp_port,
            "saved": True,
        },
    )


@router.post("/settings/test")
async def send_test_alert(
    request: Request,
    recipient: str = Form(...),
    current_user: AdminUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Send a test alert email to verify SMTP settings, using the saved config."""
    recipient = _validate_email_target(recipient)
    success, detail = await send_test_email(recipient, db)
    return templates.TemplateResponse(
        request,
        "partials/alerts_test_result.html",
        {"success": success, "detail": detail},
    )
