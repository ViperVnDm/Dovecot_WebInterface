"""Alert rule and settings tests."""

import pytest


RULE_PAYLOAD = {
    "name": "High disk usage",
    "rule_type": "storage",
    "threshold_operator": "gt",
    "threshold_value": "80",
    "notification_type": "email",
    "notification_target": "admin@example.com",
    "cooldown_minutes": "60",
}


@pytest.mark.asyncio
async def test_create_alert_rule(auth_client):
    ac, _ = auth_client
    resp = await ac.post("/api/alerts/rules", data=RULE_PAYLOAD)
    assert resp.status_code == 200
    assert b"High disk usage" in resp.content


@pytest.mark.asyncio
async def test_create_alert_rule_appears_in_list(auth_client):
    ac, _ = auth_client
    await ac.post("/api/alerts/rules", data=RULE_PAYLOAD)
    resp = await ac.get("/partials/alerts/rules")
    assert resp.status_code == 200
    assert b"High disk usage" in resp.content


@pytest.mark.asyncio
async def test_toggle_alert_rule(auth_client):
    ac, _ = auth_client
    # Create rule
    create_resp = await ac.post("/api/alerts/rules", data=RULE_PAYLOAD)
    # Extract rule ID from the response content (look for data-rule-id attribute)
    content = create_resp.text
    import re
    match = re.search(r'data-rule-id="(\d+)"', content)
    assert match, "Could not find rule ID in response"
    rule_id = match.group(1)

    # Toggle (disable)
    resp = await ac.post(f"/api/alerts/rules/{rule_id}/toggle")
    assert resp.status_code == 200
    assert b"Enable" in resp.content  # Was enabled, now shows Enable button

    # Toggle again (re-enable)
    resp2 = await ac.post(f"/api/alerts/rules/{rule_id}/toggle")
    assert resp2.status_code == 200
    assert b"Disable" in resp2.content


@pytest.mark.asyncio
async def test_edit_alert_rule(auth_client):
    ac, _ = auth_client
    create_resp = await ac.post("/api/alerts/rules", data=RULE_PAYLOAD)
    import re
    match = re.search(r'data-rule-id="(\d+)"', create_resp.text)
    rule_id = match.group(1)

    updated = {**RULE_PAYLOAD, "name": "Critical disk usage", "threshold_value": "90"}
    resp = await ac.patch(f"/api/alerts/rules/{rule_id}", data=updated)
    assert resp.status_code == 200
    assert b"Critical disk usage" in resp.content
    assert b"High disk usage" not in resp.content


@pytest.mark.asyncio
async def test_delete_alert_rule(auth_client):
    ac, _ = auth_client
    create_resp = await ac.post("/api/alerts/rules", data=RULE_PAYLOAD)
    import re
    match = re.search(r'data-rule-id="(\d+)"', create_resp.text)
    rule_id = match.group(1)

    resp = await ac.delete(f"/api/alerts/rules/{rule_id}")
    assert resp.status_code == 200
    assert b"High disk usage" not in resp.content


@pytest.mark.asyncio
async def test_alert_settings_load(auth_client):
    ac, _ = auth_client
    resp = await ac.get("/api/alerts/settings")
    assert resp.status_code == 200
    # Default check interval of 5 should be present
    assert b"5" in resp.content


@pytest.mark.asyncio
async def test_alert_settings_update(auth_client):
    ac, _ = auth_client
    resp = await ac.post("/api/alerts/settings", data={
        "check_interval": "15",
        "smtp_from": "alerts@nrstuff.com",
        "smtp_host": "localhost",
        "smtp_port": "25",
    })
    assert resp.status_code == 200
    assert b"15" in resp.content
    assert b"alerts@nrstuff.com" in resp.content


@pytest.mark.asyncio
async def test_alert_history_empty_initially(auth_client):
    ac, _ = auth_client
    resp = await ac.get("/partials/alerts/history")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_alert_rules_unauthenticated(client):
    ac, _ = client
    resp = await ac.post("/api/alerts/rules", data=RULE_PAYLOAD)
    assert resp.status_code == 401
