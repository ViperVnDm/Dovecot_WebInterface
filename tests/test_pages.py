"""Smoke tests: every top-level page renders.

Catches server-side template errors (Jinja syntax, bad macro imports, missing
context) — important because the Phase D UI edits aren't otherwise unit-tested.
"""

import pytest

PAGES = [
    "/dashboard", "/users", "/queue", "/logs", "/firewall",
    "/storage", "/alerts", "/agent", "/audit",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PAGES)
async def test_page_renders(auth_client, path):
    ac, _ = auth_client
    resp = await ac.get(path)
    assert resp.status_code == 200, f"{path} -> {resp.status_code}"
    # Confirms base.html actually rendered (not a bare error body).
    assert b"Mail Server Admin" in resp.content


@pytest.mark.asyncio
async def test_agent_page_sections_are_ordered_and_start_collapsed(auth_client):
    """Pending work first, then history, then settings — all collapsed by default.

    The pending list can run to hundreds of entries; collapsed cards keep the
    page an overview instead of burying Recent Runs below it.
    """
    ac, _ = auth_client
    html = (await ac.get("/agent")).text

    positions = [html.index(f">{title}</h2>")
                 for title in ("Pending Suggestions", "Recent Runs", "Agent Settings")]
    assert positions == sorted(positions)

    for key in ("agent_pending", "agent_runs", "agent_config"):
        assert f"$persist(false).as('card_{key}')" in html
    # The header pill the suggestions partial fills in out-of-band.
    assert 'id="agent-pending-count"' in html
    # "Run now" reports into Recent Runs, so it has to open that card.
    assert "$dispatch('open-card', 'agent_runs')" in html
