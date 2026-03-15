"""Background task that periodically evaluates alert rules and sends notifications."""

import asyncio
import logging
import shutil
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.core.permissions import get_helper_client, PrivilegedHelperError
from app.database import AlertHistory, AlertRule, AppSetting, async_session

logger = logging.getLogger(__name__)
settings = get_settings()

DEFAULT_CHECK_INTERVAL = 5  # minutes


async def get_check_interval() -> int:
    """Read check interval from DB settings, falling back to default."""
    async with async_session() as db:
        result = await db.execute(
            select(AppSetting).where(AppSetting.key == "alert_check_interval")
        )
        setting = result.scalar_one_or_none()
        if setting:
            try:
                return max(1, int(setting.value))
            except ValueError:
                pass
    return DEFAULT_CHECK_INTERVAL


async def _get_metric(rule_type: str) -> float | None:
    """Return the current value for a metric type, or None on error."""
    if rule_type == "storage":
        try:
            usage = shutil.disk_usage(str(settings.mail_spool_path))
            return round((usage.used / usage.total) * 100, 1)
        except Exception as e:
            logger.error(f"Failed to get disk usage: {e}")
            return None

    if rule_type in ("queue_size", "deferred_count"):
        helper = get_helper_client()
        try:
            stats = await helper.get_queue_stats()
            return float(stats.get("deferred" if rule_type == "deferred_count" else "total", 0))
        except PrivilegedHelperError as e:
            logger.error(f"Failed to get queue stats: {e.message}")
            return None

    logger.warning(f"Unknown rule_type: {rule_type}")
    return None


def _evaluate(current: float, operator: str, threshold: float) -> bool:
    return {
        "gt": current > threshold,
        "gte": current >= threshold,
        "lt": current < threshold,
        "lte": current <= threshold,
        "eq": current == threshold,
    }.get(operator, False)


def _send_email(rule: AlertRule, current_value: float, message: str) -> bool:
    """Send an email notification via local SMTP. Returns True on success."""
    try:
        body = (
            f"Alert rule '{rule.name}' has triggered.\n\n"
            f"{message}\n\n"
            f"Current value : {current_value}\n"
            f"Threshold     : {rule.threshold_operator} {rule.threshold_value}\n"
            f"Cooldown      : {rule.cooldown_minutes} minutes\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = f"[Mail Admin] Alert: {rule.name}"
        msg["From"] = settings.smtp_from
        msg["To"] = rule.notification_target

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            smtp.sendmail(settings.smtp_from, [rule.notification_target], msg.as_string())

        logger.info(f"Alert notification sent to {rule.notification_target} for rule '{rule.name}'")
        return True
    except Exception as e:
        logger.error(f"Failed to send alert email for rule '{rule.name}': {e}")
        return False


def _send_webhook(rule: AlertRule, current_value: float, message: str) -> bool:
    """POST a JSON payload to the webhook URL. Returns True on success."""
    import json
    import urllib.request

    payload = json.dumps({
        "rule": rule.name,
        "rule_type": rule.rule_type,
        "current_value": current_value,
        "threshold_operator": rule.threshold_operator,
        "threshold_value": rule.threshold_value,
        "message": message,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
    }).encode()

    try:
        req = urllib.request.Request(
            rule.notification_target,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
        logger.info(f"Webhook delivered for rule '{rule.name}' to {rule.notification_target}")
        return True
    except Exception as e:
        logger.error(f"Webhook failed for rule '{rule.name}': {e}")
        return False


def _notify(rule: AlertRule, current_value: float, message: str) -> bool:
    if rule.notification_type == "email":
        return _send_email(rule, current_value, message)
    if rule.notification_type == "webhook":
        return _send_webhook(rule, current_value, message)
    return False


async def check_alerts() -> None:
    """Evaluate all enabled rules and fire notifications where needed."""
    async with async_session() as db:
        result = await db.execute(
            select(AlertRule).where(AlertRule.is_enabled == True)
        )
        rules = result.scalars().all()

        for rule in rules:
            try:
                current_value = await _get_metric(rule.rule_type)
                if current_value is None:
                    continue

                if not _evaluate(current_value, rule.threshold_operator, rule.threshold_value):
                    continue

                # Enforce per-rule cooldown
                cooldown_cutoff = datetime.now(timezone.utc) - timedelta(minutes=rule.cooldown_minutes)
                recent = await db.execute(
                    select(AlertHistory)
                    .where(AlertHistory.rule_id == rule.id)
                    .where(AlertHistory.triggered_at > cooldown_cutoff)
                    .limit(1)
                )
                if recent.scalar_one_or_none() is not None:
                    continue  # Still within cooldown window

                op_labels = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "=="}
                op = op_labels.get(rule.threshold_operator, rule.threshold_operator)
                message = (
                    f"{rule.rule_type} is {current_value} "
                    f"({op} {rule.threshold_value} threshold exceeded)"
                )

                notification_sent = _notify(rule, current_value, message)

                db.add(AlertHistory(
                    rule_id=rule.id,
                    current_value=current_value,
                    message=message,
                    notification_sent=notification_sent,
                ))
                logger.info(f"Alert triggered: '{rule.name}' current={current_value}")

            except Exception:
                logger.exception(f"Error evaluating rule '{rule.name}'")

        await db.commit()


async def alert_checker_loop() -> None:
    """Long-running background task. Sleeps for the configured interval between checks."""
    logger.info("Alert checker background task started")
    while True:
        interval = await get_check_interval()
        logger.debug(f"Next alert check in {interval} minutes")
        await asyncio.sleep(interval * 60)
        try:
            await check_alerts()
        except Exception:
            logger.exception("Unhandled error in alert checker")
