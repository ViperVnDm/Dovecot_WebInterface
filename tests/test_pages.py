"""Smoke tests: every top-level page renders.

Catches server-side template errors (Jinja syntax, bad macro imports, missing
context) — important because the Phase D UI edits aren't otherwise unit-tested.
"""

import pytest

PAGES = [
    "/dashboard", "/users", "/queue", "/logs",
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
