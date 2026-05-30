"""Mail queue action route tests.

These guard the headline bug from the review: the queue page buttons were
wired to /api/queue/* routes that all returned 501, so every flush/hold/
release/delete silently did nothing. Each action must now call the matching
privileged-helper method and return the refreshed queue table partial (200).
"""

import pytest

QID = "ABCDEF123456"


@pytest.mark.asyncio
async def test_flush_all_queue(auth_client):
    ac, mock_helper = auth_client
    resp = await ac.post("/api/queue/flush")
    assert resp.status_code == 200
    mock_helper.flush_queue.assert_called_once()


@pytest.mark.asyncio
async def test_flush_message(auth_client):
    ac, mock_helper = auth_client
    resp = await ac.post(f"/api/queue/{QID}/flush")
    assert resp.status_code == 200
    mock_helper.flush_message.assert_called_once_with(QID)


@pytest.mark.asyncio
async def test_hold_message(auth_client):
    ac, mock_helper = auth_client
    resp = await ac.post(f"/api/queue/{QID}/hold")
    assert resp.status_code == 200
    mock_helper.hold_message.assert_called_once_with(QID)


@pytest.mark.asyncio
async def test_release_message(auth_client):
    ac, mock_helper = auth_client
    resp = await ac.post(f"/api/queue/{QID}/release")
    assert resp.status_code == 200
    mock_helper.release_message.assert_called_once_with(QID)


@pytest.mark.asyncio
async def test_delete_message(auth_client):
    ac, mock_helper = auth_client
    resp = await ac.delete(f"/api/queue/{QID}")
    assert resp.status_code == 200
    mock_helper.delete_message.assert_called_once_with(QID)


@pytest.mark.asyncio
async def test_action_returns_queue_table_partial(auth_client):
    """A successful action re-renders the table so HTMX can swap it in."""
    ac, mock_helper = auth_client
    mock_helper.list_queue.return_value = []
    resp = await ac.post("/api/queue/flush")
    assert resp.status_code == 200
    # Empty-state copy from partials/queue_table.html
    assert b"Queue is empty" in resp.content


@pytest.mark.asyncio
async def test_helper_failure_surfaces_error_code(auth_client):
    """If the helper rejects the action, the route returns its error code."""
    from app.core.permissions import PrivilegedHelperError

    ac, mock_helper = auth_client
    mock_helper.delete_message.side_effect = PrivilegedHelperError(
        "Invalid queue ID format", code=400
    )
    resp = await ac.delete(f"/api/queue/{QID}")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_queue_action_requires_auth(client):
    """Unauthenticated callers are rejected (CSRF is primed by the fixture)."""
    ac, _ = client  # not logged in
    resp = await ac.post("/api/queue/flush")
    assert resp.status_code == 401
