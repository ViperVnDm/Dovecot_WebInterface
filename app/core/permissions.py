"""Privileged helper IPC client."""

import asyncio
import json
from pathlib import Path
from typing import Any

from app.config import get_settings

settings = get_settings()


class PrivilegedHelperError(Exception):
    """Error from privileged helper."""

    def __init__(self, message: str, code: int = 500):
        self.message = message
        self.code = code
        super().__init__(message)


class PrivilegedHelperClient:
    """Client for communicating with the privileged helper daemon."""

    def __init__(self, socket_path: Path | None = None):
        self.socket_path = socket_path or settings.helper_socket_path

    async def _send_command(self, command: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a command to the privileged helper and return the response."""
        try:
            reader, writer = await asyncio.open_unix_connection(str(self.socket_path), limit=4 * 1024 * 1024)  # 4 MB
        except (FileNotFoundError, ConnectionRefusedError) as e:
            raise PrivilegedHelperError(
                f"Cannot connect to privileged helper: {e}",
                code=503,
            )

        try:
            # Send request
            request = json.dumps({"command": command, "params": params})
            writer.write(request.encode() + b"\n")
            await writer.drain()

            # Read response
            response_data = await reader.readline()
            if not response_data:
                raise PrivilegedHelperError("Empty response from helper", code=500)

            response = json.loads(response_data.decode())

            if "error" in response:
                raise PrivilegedHelperError(
                    response["error"],
                    code=response.get("code", 500),
                )

            return response

        finally:
            writer.close()
            await writer.wait_closed()

    # User management commands
    async def create_user(
        self,
        username: str,
        password: str,
        quota_mb: int = 0,
    ) -> dict[str, Any]:
        """Create a new system user for mail."""
        return await self._send_command(
            "create_user",
            {"username": username, "password": password, "quota_mb": quota_mb},
        )

    async def delete_user(self, username: str, delete_mail: bool = False) -> dict[str, Any]:
        """Delete a system user."""
        return await self._send_command(
            "delete_user",
            {"username": username, "delete_mail": delete_mail},
        )

    async def set_password(self, username: str, password: str) -> dict[str, Any]:
        """Set a user's password."""
        return await self._send_command(
            "set_password",
            {"username": username, "password": password},
        )

    async def set_quota(self, username: str, quota_mb: int) -> dict[str, Any]:
        """Set a user's mail quota."""
        return await self._send_command(
            "set_quota",
            {"username": username, "quota_mb": quota_mb},
        )

    async def list_users(self) -> list[dict[str, Any]]:
        """List all mail users."""
        response = await self._send_command("list_users", {})
        return response.get("users", [])

    async def get_user(self, username: str) -> dict[str, Any] | None:
        """Get details for a specific user."""
        response = await self._send_command("get_user", {"username": username})
        return response.get("user")

    async def get_quota(self, username: str) -> dict[str, Any]:
        """Get quota info for a user."""
        return await self._send_command("get_quota", {"username": username})

    # Queue management commands
    async def list_queue(self, queue_name: str | None = None) -> list[dict[str, Any]]:
        """List mail queue."""
        response = await self._send_command(
            "list_queue",
            {"queue_name": queue_name} if queue_name else {},
        )
        return response.get("messages", [])

    async def get_queue_stats(self) -> dict[str, int]:
        """Get queue statistics."""
        return await self._send_command("queue_stats", {})

    async def flush_queue(self) -> dict[str, Any]:
        """Flush entire mail queue."""
        return await self._send_command("flush_queue", {})

    async def flush_message(self, queue_id: str) -> dict[str, Any]:
        """Flush a specific message."""
        return await self._send_command("flush_message", {"queue_id": queue_id})

    async def delete_message(self, queue_id: str) -> dict[str, Any]:
        """Delete a message from the queue."""
        return await self._send_command("delete_message", {"queue_id": queue_id})

    async def hold_message(self, queue_id: str) -> dict[str, Any]:
        """Put a message on hold."""
        return await self._send_command("hold_message", {"queue_id": queue_id})

    async def release_message(self, queue_id: str) -> dict[str, Any]:
        """Release a message from hold."""
        return await self._send_command("release_message", {"queue_id": queue_id})

    # Log commands
    async def read_logs(
        self,
        lines: int = 100,
        level: str | None = None,
        service: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        """Read mail logs."""
        params = {"lines": lines}
        if level:
            params["level"] = level
        if service:
            params["service"] = service
        if search:
            params["search"] = search

        response = await self._send_command("read_logs", params)
        return response.get("entries", [])

    async def get_log_stats(self) -> dict[str, int]:
        """Get today's sent/received/bounced/error counts from mail.log."""
        return await self._send_command("get_log_stats", {})

    async def get_mailbox_sizes(self) -> list[dict[str, Any]]:
        """Get mailbox sizes for all users."""
        response = await self._send_command("mailbox_sizes", {})
        return response.get("mailboxes", [])

    # IP ban commands
    async def ban_ip(self, ip: str) -> dict[str, Any]:
        """Block an IP via UFW."""
        return await self._send_command("ban_ip", {"ip": ip})

    async def unban_ip(self, ip: str) -> dict[str, Any]:
        """Remove a UFW ban for an IP."""
        return await self._send_command("unban_ip", {"ip": ip})

    async def list_banned_ips(self) -> list[str]:
        """List IPs currently blocked by UFW."""
        response = await self._send_command("list_banned_ips", {})
        return response.get("banned_ips", [])


# Singleton instance
_helper_client: PrivilegedHelperClient | None = None


def get_helper_client() -> PrivilegedHelperClient:
    """Get the privileged helper client singleton."""
    global _helper_client
    if _helper_client is None:
        _helper_client = PrivilegedHelperClient()
    return _helper_client
