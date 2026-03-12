#!/usr/bin/env python3
"""
Privileged helper daemon for mail server administration.

This server runs as root via systemd and accepts commands over a Unix socket.
Only whitelisted commands are accepted, with strict input validation.

SECURITY: This is a privilege boundary. All inputs must be validated.
"""

import asyncio
import grp
import json
import logging
import os
import pwd
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("privileged-helper")

# Configuration
SOCKET_PATH = Path(os.environ.get("HELPER_SOCKET_PATH", "/run/dovecot-webadmin/helper.sock"))
MAIL_GROUP = os.environ.get("MAIL_GROUP", "mail")
MAIL_LOG_PATH = Path(os.environ.get("MAIL_LOG_PATH", "/var/log/mail.log"))
MAIL_SPOOL_PATH = Path(os.environ.get("MAIL_SPOOL_PATH", "/var/mail"))

# Validation patterns
USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
QUEUE_ID_PATTERN = re.compile(r"^[A-F0-9]{10,12}$")

# Reserved usernames that cannot be created/deleted
RESERVED_USERNAMES = frozenset([
    "root", "admin", "postfix", "dovecot", "mail", "nobody", "daemon",
    "bin", "sys", "sync", "games", "man", "lp", "news", "uucp",
    "proxy", "www-data", "backup", "list", "irc", "gnats", "sshd",
])


class CommandError(Exception):
    """Error executing a command."""

    def __init__(self, message: str, code: int = 400):
        self.message = message
        self.code = code
        super().__init__(message)


def validate_username(username: str) -> str:
    """Validate and return username, or raise CommandError."""
    if not username:
        raise CommandError("Username is required", 400)
    if not USERNAME_PATTERN.match(username):
        raise CommandError(
            "Username must be 3-32 chars, start with letter, contain only lowercase, numbers, _, -",
            400,
        )
    if username in RESERVED_USERNAMES:
        raise CommandError(f"Username '{username}' is reserved", 400)
    return username


def validate_queue_id(queue_id: str) -> str:
    """Validate and return queue ID, or raise CommandError."""
    if not queue_id:
        raise CommandError("Queue ID is required", 400)
    if not QUEUE_ID_PATTERN.match(queue_id):
        raise CommandError("Invalid queue ID format", 400)
    return queue_id


def run_command(cmd: list[str], input_data: str | None = None) -> tuple[str, str, int]:
    """
    Run a command safely without shell.

    Returns (stdout, stderr, returncode).
    """
    logger.info(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            input=input_data,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        raise CommandError("Command timed out", 500)
    except Exception as e:
        raise CommandError(f"Command failed: {e}", 500)


# ============== User Management Commands ==============


def cmd_create_user(params: dict[str, Any]) -> dict[str, Any]:
    """Create a new mail user."""
    username = validate_username(params.get("username", ""))
    password = params.get("password", "")
    quota_mb = int(params.get("quota_mb", 0))

    if not password or len(password) < 8:
        raise CommandError("Password must be at least 8 characters", 400)

    # Check if user exists
    try:
        pwd.getpwnam(username)
        raise CommandError(f"User '{username}' already exists", 409)
    except KeyError:
        pass  # User doesn't exist, good

    # Get mail group GID
    try:
        mail_gid = grp.getgrnam(MAIL_GROUP).gr_gid
    except KeyError:
        raise CommandError(f"Mail group '{MAIL_GROUP}' not found", 500)

    # Create user with mail group, no login shell
    stdout, stderr, rc = run_command([
        "useradd",
        "-m",  # Create home directory
        "-s", "/sbin/nologin",  # No login shell
        "-g", str(mail_gid),  # Primary group
        "-d", str(MAIL_SPOOL_PATH / username),  # Home = mail directory
        username,
    ])

    if rc != 0:
        raise CommandError(f"Failed to create user: {stderr}", 500)

    # Set password
    stdout, stderr, rc = run_command(
        ["chpasswd"],
        input_data=f"{username}:{password}",
    )

    if rc != 0:
        # Cleanup: delete user
        run_command(["userdel", "-r", username])
        raise CommandError(f"Failed to set password: {stderr}", 500)

    # Set quota if specified
    if quota_mb > 0:
        try:
            cmd_set_quota({"username": username, "quota_mb": quota_mb})
        except CommandError as e:
            logger.warning(f"Failed to set quota for {username}: {e.message}")

    # Get user info
    user_info = pwd.getpwnam(username)

    logger.info(f"Created user: {username}")
    return {
        "success": True,
        "user": {
            "username": username,
            "uid": user_info.pw_uid,
            "gid": user_info.pw_gid,
            "home": user_info.pw_dir,
            "quota_mb": quota_mb,
        },
    }


def cmd_delete_user(params: dict[str, Any]) -> dict[str, Any]:
    """Delete a mail user."""
    username = validate_username(params.get("username", ""))
    delete_mail = bool(params.get("delete_mail", False))

    # Check if user exists
    try:
        pwd.getpwnam(username)
    except KeyError:
        raise CommandError(f"User '{username}' not found", 404)

    # Delete user
    cmd = ["userdel"]
    if delete_mail:
        cmd.append("-r")  # Remove home directory and mail spool
    cmd.append(username)

    stdout, stderr, rc = run_command(cmd)

    if rc != 0:
        raise CommandError(f"Failed to delete user: {stderr}", 500)

    logger.info(f"Deleted user: {username} (delete_mail={delete_mail})")
    return {"success": True}


def cmd_set_password(params: dict[str, Any]) -> dict[str, Any]:
    """Set a user's password."""
    username = validate_username(params.get("username", ""))
    password = params.get("password", "")

    if not password or len(password) < 8:
        raise CommandError("Password must be at least 8 characters", 400)

    # Check if user exists
    try:
        pwd.getpwnam(username)
    except KeyError:
        raise CommandError(f"User '{username}' not found", 404)

    stdout, stderr, rc = run_command(
        ["chpasswd"],
        input_data=f"{username}:{password}",
    )

    if rc != 0:
        raise CommandError(f"Failed to set password: {stderr}", 500)

    logger.info(f"Password changed for: {username}")
    return {"success": True}


def cmd_set_quota(params: dict[str, Any]) -> dict[str, Any]:
    """Set a user's mail quota using doveadm."""
    username = validate_username(params.get("username", ""))
    quota_mb = int(params.get("quota_mb", 0))

    # Check if user exists
    try:
        pwd.getpwnam(username)
    except KeyError:
        raise CommandError(f"User '{username}' not found", 404)

    # Set quota via doveadm (if available)
    # This assumes Dovecot is configured with quota plugin
    quota_value = f"{quota_mb}M" if quota_mb > 0 else "0"

    stdout, stderr, rc = run_command([
        "doveadm", "quota", "set", "-u", username, "STORAGE", quota_value,
    ])

    if rc != 0:
        # doveadm might not be available or quota not configured
        logger.warning(f"doveadm quota set failed: {stderr}")
        raise CommandError(f"Failed to set quota: {stderr}", 500)

    logger.info(f"Quota set for {username}: {quota_mb}MB")
    return {"success": True}


def cmd_get_quota(params: dict[str, Any]) -> dict[str, Any]:
    """Get a user's quota usage."""
    username = validate_username(params.get("username", ""))

    try:
        pwd.getpwnam(username)
    except KeyError:
        raise CommandError(f"User '{username}' not found", 404)

    stdout, stderr, rc = run_command([
        "doveadm", "quota", "get", "-u", username,
    ])

    if rc != 0:
        raise CommandError(f"Failed to get quota: {stderr}", 500)

    # Parse doveadm quota output
    # Format: "Quota name Type    Value  Limit  %"
    quota_info = {"username": username, "storage_used": 0, "storage_limit": 0}

    for line in stdout.strip().split("\n")[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 4 and parts[1] == "STORAGE":
            quota_info["storage_used"] = int(parts[2]) * 1024  # KB to bytes
            quota_info["storage_limit"] = int(parts[3]) * 1024 if parts[3] != "-" else 0

    return quota_info


def cmd_list_users(params: dict[str, Any]) -> dict[str, Any]:
    """List all mail users."""
    users = []

    try:
        mail_gid = grp.getgrnam(MAIL_GROUP).gr_gid
    except KeyError:
        mail_gid = None

    # List users in mail group
    for user in pwd.getpwall():
        # Filter to mail users (in mail group, home in mail spool)
        if mail_gid and user.pw_gid == mail_gid:
            if user.pw_name not in RESERVED_USERNAMES:
                users.append({
                    "username": user.pw_name,
                    "uid": user.pw_uid,
                    "gid": user.pw_gid,
                    "home": user.pw_dir,
                })

    return {"users": users}


def cmd_get_user(params: dict[str, Any]) -> dict[str, Any]:
    """Get details for a specific user."""
    username = validate_username(params.get("username", ""))

    try:
        user = pwd.getpwnam(username)
    except KeyError:
        raise CommandError(f"User '{username}' not found", 404)

    return {
        "user": {
            "username": user.pw_name,
            "uid": user.pw_uid,
            "gid": user.pw_gid,
            "home": user.pw_dir,
        }
    }


# ============== Queue Management Commands ==============


def cmd_list_queue(params: dict[str, Any]) -> dict[str, Any]:
    """List messages in the mail queue."""
    queue_name = params.get("queue_name")

    # Use postqueue -j for JSON output
    stdout, stderr, rc = run_command(["postqueue", "-j"])

    if rc != 0:
        raise CommandError(f"Failed to list queue: {stderr}", 500)

    messages = []
    for line in stdout.strip().split("\n"):
        if not line:
            continue
        try:
            msg = json.loads(line)
            # Filter by queue name if specified
            if queue_name and msg.get("queue_name") != queue_name:
                continue
            messages.append({
                "queue_id": msg.get("queue_id"),
                "queue_name": msg.get("queue_name"),
                "sender": msg.get("sender"),
                "recipients": [r.get("address") for r in msg.get("recipients", [])],
                "size": msg.get("message_size", 0),
                "arrival_time": msg.get("arrival_time"),
                "reason": msg.get("recipients", [{}])[0].get("delay_reason"),
            })
        except json.JSONDecodeError:
            continue

    return {"messages": messages}


def cmd_queue_stats(params: dict[str, Any]) -> dict[str, Any]:
    """Get queue statistics."""
    result = cmd_list_queue({})
    messages = result.get("messages", [])

    stats = {"active": 0, "deferred": 0, "hold": 0, "incoming": 0, "total": len(messages)}

    for msg in messages:
        queue_name = msg.get("queue_name", "")
        if queue_name in stats:
            stats[queue_name] += 1

    return stats


def cmd_flush_queue(params: dict[str, Any]) -> dict[str, Any]:
    """Flush the entire mail queue."""
    stdout, stderr, rc = run_command(["postqueue", "-f"])

    if rc != 0:
        raise CommandError(f"Failed to flush queue: {stderr}", 500)

    logger.info("Flushed mail queue")
    return {"success": True}


def cmd_flush_message(params: dict[str, Any]) -> dict[str, Any]:
    """Flush a specific message."""
    queue_id = validate_queue_id(params.get("queue_id", ""))

    stdout, stderr, rc = run_command(["postqueue", "-i", queue_id])

    if rc != 0:
        raise CommandError(f"Failed to flush message: {stderr}", 500)

    logger.info(f"Flushed message: {queue_id}")
    return {"success": True}


def cmd_delete_message(params: dict[str, Any]) -> dict[str, Any]:
    """Delete a message from the queue."""
    queue_id = validate_queue_id(params.get("queue_id", ""))

    stdout, stderr, rc = run_command(["postsuper", "-d", queue_id])

    if rc != 0:
        raise CommandError(f"Failed to delete message: {stderr}", 500)

    logger.info(f"Deleted message: {queue_id}")
    return {"success": True}


def cmd_hold_message(params: dict[str, Any]) -> dict[str, Any]:
    """Put a message on hold."""
    queue_id = validate_queue_id(params.get("queue_id", ""))

    stdout, stderr, rc = run_command(["postsuper", "-h", queue_id])

    if rc != 0:
        raise CommandError(f"Failed to hold message: {stderr}", 500)

    logger.info(f"Message on hold: {queue_id}")
    return {"success": True}


def cmd_release_message(params: dict[str, Any]) -> dict[str, Any]:
    """Release a message from hold."""
    queue_id = validate_queue_id(params.get("queue_id", ""))

    stdout, stderr, rc = run_command(["postsuper", "-H", queue_id])

    if rc != 0:
        raise CommandError(f"Failed to release message: {stderr}", 500)

    logger.info(f"Released message: {queue_id}")
    return {"success": True}


# ============== Log Commands ==============


def cmd_read_logs(params: dict[str, Any]) -> dict[str, Any]:
    """Read mail log entries."""
    lines = min(int(params.get("lines", 100)), 1000)
    level = params.get("level")
    service = params.get("service")
    search = params.get("search")

    if not MAIL_LOG_PATH.exists():
        return {"entries": []}

    # Read last N lines
    stdout, stderr, rc = run_command(["tail", "-n", str(lines), str(MAIL_LOG_PATH)])

    if rc != 0:
        raise CommandError(f"Failed to read logs: {stderr}", 500)

    entries = []
    log_pattern = re.compile(
        r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)"
    )

    for line in stdout.strip().split("\n"):
        if not line:
            continue

        match = log_pattern.match(line)
        if match:
            timestamp, host, svc, pid, message = match.groups()

            # Filter by service
            if service and not svc.lower().startswith(service.lower()):
                continue

            # Filter by search term
            if search and search.lower() not in line.lower():
                continue

            # Determine level
            entry_level = "info"
            if "error" in message.lower() or "fatal" in message.lower():
                entry_level = "error"
            elif "warning" in message.lower() or "warn" in message.lower():
                entry_level = "warning"

            # Filter by level
            if level and entry_level != level:
                continue

            entries.append({
                "timestamp": timestamp,
                "host": host,
                "service": svc,
                "pid": int(pid) if pid else None,
                "level": entry_level,
                "message": message,
            })

    return {"entries": entries}


def cmd_mailbox_sizes(params: dict[str, Any]) -> dict[str, Any]:
    """Get mailbox sizes for all users."""
    mailboxes = []

    if not MAIL_SPOOL_PATH.exists():
        return {"mailboxes": []}

    for user_dir in MAIL_SPOOL_PATH.iterdir():
        if user_dir.is_dir():
            # Calculate directory size
            total_size = 0
            message_count = 0
            for f in user_dir.rglob("*"):
                if f.is_file():
                    total_size += f.stat().st_size
                    message_count += 1

            mailboxes.append({
                "username": user_dir.name,
                "size_bytes": total_size,
                "message_count": message_count,
            })

    # Sort by size descending
    mailboxes.sort(key=lambda x: x["size_bytes"], reverse=True)

    return {"mailboxes": mailboxes}


# ============== Command Dispatcher ==============


COMMANDS = {
    # User management
    "create_user": cmd_create_user,
    "delete_user": cmd_delete_user,
    "set_password": cmd_set_password,
    "set_quota": cmd_set_quota,
    "get_quota": cmd_get_quota,
    "list_users": cmd_list_users,
    "get_user": cmd_get_user,
    # Queue management
    "list_queue": cmd_list_queue,
    "queue_stats": cmd_queue_stats,
    "flush_queue": cmd_flush_queue,
    "flush_message": cmd_flush_message,
    "delete_message": cmd_delete_message,
    "hold_message": cmd_hold_message,
    "release_message": cmd_release_message,
    # Logs
    "read_logs": cmd_read_logs,
    "mailbox_sizes": cmd_mailbox_sizes,
}


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle a client connection."""
    addr = writer.get_extra_info("peername")
    logger.debug(f"Client connected: {addr}")

    try:
        while True:
            data = await reader.readline()
            if not data:
                break

            try:
                request = json.loads(data.decode())
                command = request.get("command")
                params = request.get("params", {})

                if command not in COMMANDS:
                    response = {"error": f"Unknown command: {command}", "code": 400}
                else:
                    try:
                        response = COMMANDS[command](params)
                    except CommandError as e:
                        response = {"error": e.message, "code": e.code}
                    except Exception as e:
                        logger.exception(f"Command failed: {command}")
                        response = {"error": str(e), "code": 500}

            except json.JSONDecodeError:
                response = {"error": "Invalid JSON", "code": 400}

            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()

    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.exception("Client handler error")
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    """Main entry point."""
    # Ensure running as root
    if os.geteuid() != 0:
        logger.error("This daemon must run as root")
        sys.exit(1)

    # Create socket directory
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Remove existing socket
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    # Start server
    server = await asyncio.start_unix_server(handle_client, path=str(SOCKET_PATH))

    # Set socket permissions (allow www-data to connect)
    os.chmod(SOCKET_PATH, 0o660)
    try:
        www_data_gid = grp.getgrnam("www-data").gr_gid
        os.chown(SOCKET_PATH, 0, www_data_gid)
    except KeyError:
        logger.warning("www-data group not found, socket permissions may be incorrect")

    logger.info(f"Privileged helper listening on {SOCKET_PATH}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down")
