"""Dashboard partial tests."""

import pytest


@pytest.mark.asyncio
async def test_dashboard_stats_uses_cheap_user_count(auth_client):
    """The stats card must use count_users (cheap) and NOT list_users, which
    walks every maildir — that path ran every 30s on the live 1 GB box."""
    ac, mock_helper = auth_client
    resp = await ac.get("/partials/dashboard/stats")
    assert resp.status_code == 200
    mock_helper.count_users.assert_called()
    mock_helper.list_users.assert_not_called()
