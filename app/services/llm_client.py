"""Anthropic client for log triage.

Wraps the Anthropic SDK with:
- prompt caching on the static system prompt (mail-provider CIDR list + rubric)
- forced tool-use output for a strict JSON schema
- a single triage_ips() entry point used by app/services/log_agent.py

The agent never applies actions itself — it only returns suggestions for a
human to approve via the web UI. That keeps the surface area small here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.config import get_settings

logger = logging.getLogger(__name__)


# Pricing for claude-haiku-4-5 (USD per million tokens). Update if rates change.
INPUT_COST_PER_MTOK = 1.0
OUTPUT_COST_PER_MTOK = 5.0
CACHE_WRITE_COST_PER_MTOK = 1.25
CACHE_READ_COST_PER_MTOK = 0.10


@dataclass
class IPSummary:
    """Compact per-IP summary handed to the LLM."""

    ip: str
    total_events: int
    services_touched: list[str]
    time_range: str
    sample_lines: list[str]


@dataclass
class Suggestion:
    """One triage decision returned by the LLM."""

    target: str
    action: str  # "ban" | "allowlist" | "ignore"
    confidence: int
    reason: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class TokenUsage:
    """Token / cost accounting for a single LLM call."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0

    @property
    def cost_usd(self) -> float:
        return (
            self.input_tokens * INPUT_COST_PER_MTOK
            + self.output_tokens * OUTPUT_COST_PER_MTOK
            + self.cache_creation_tokens * CACHE_WRITE_COST_PER_MTOK
            + self.cache_read_tokens * CACHE_READ_COST_PER_MTOK
        ) / 1_000_000


# Well-known mail-provider ranges. The model uses these to flag legitimate
# sources for the allowlist instead of banning them. Not exhaustive — kept
# short on purpose so the cached prefix stays small.
_KNOWN_MAIL_PROVIDERS = """
Google (Gmail / Google Workspace): 64.233.160.0/19, 66.102.0.0/20, 66.249.80.0/20, 209.85.128.0/17, 172.217.0.0/16
Microsoft 365 / Outlook: 40.92.0.0/15, 40.107.0.0/16, 52.100.0.0/14, 104.47.0.0/17
Amazon SES: 199.255.192.0/22, 199.127.232.0/22, 54.240.0.0/18
Mailgun: 173.193.210.0/24, 209.61.151.0/24
SendGrid: 167.89.0.0/17, 168.245.0.0/17
ProtonMail: 185.70.40.0/22
Fastmail: 66.111.4.0/24, 103.168.172.0/22
Apple iCloud Mail: 17.0.0.0/8 (subset)
Zoho Mail: 136.143.176.0/20, 204.141.32.0/20
""".strip()


SYSTEM_PROMPT = f"""You are a security analyst triaging mail-server logs for a small Postfix/Dovecot/SpamAssassin/UFW deployment. For each source IP, decide one of:

- "ban": clearly malicious — SSH brute-force, repeated SMTP AUTH failures, port-scanning blocked by UFW, or login attempts for users that don't exist. High confidence (>=70).
- "allowlist": the IP belongs to a legitimate mail provider AND has successfully passed mail traffic. Recommend it for the never-ban allowlist so future heuristics don't catch it. Use this sparingly — only when you can name the provider.
- "ignore": ambiguous, single failure, or already-handled. Don't create a suggestion.

NEVER recommend banning loopback (127/8), private RFC1918 ranges unless explicitly attacking, link-local, multicast, or any IP that appears to be operating as a normal mail relay for a known provider. The helper layer enforces these constraints regardless, but be conservative.

KNOWN LEGITIMATE MAIL-SERVER RANGES (do not ban any IP that falls inside these):
{_KNOWN_MAIL_PROVIDERS}

For each input IP, return one decision via the record_suggestions tool. confidence is 0-100. reason is one short sentence citing the strongest piece of evidence.
"""


_RECORD_SUGGESTIONS_TOOL = {
    "name": "record_suggestions",
    "description": "Record one triage decision per input IP.",
    "input_schema": {
        "type": "object",
        "properties": {
            "suggestions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "Source IPv4 address"},
                        "action": {"type": "string", "enum": ["ban", "allowlist", "ignore"]},
                        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                        "reason": {"type": "string"},
                    },
                    "required": ["ip", "action", "confidence", "reason"],
                },
            }
        },
        "required": ["suggestions"],
    },
}


def _format_user_message(grouped: list[IPSummary]) -> str:
    """Render the per-IP summaries as a compact textual block."""
    lines = ["Triage the following IPs based on their log evidence:\n"]
    for s in grouped:
        lines.append(
            f"\n## {s.ip}\n"
            f"- events: {s.total_events}\n"
            f"- services: {', '.join(s.services_touched)}\n"
            f"- time_range: {s.time_range}\n"
            f"- samples:"
        )
        for ln in s.sample_lines[:5]:
            lines.append(f"    {ln}")
    return "\n".join(lines)


async def triage_ips(grouped: list[IPSummary]) -> tuple[list[Suggestion], TokenUsage, str]:
    """Send IP summaries to Claude and return parsed suggestions + usage + model."""
    if not grouped:
        return [], TokenUsage(), ""

    # Imported here so tests can patch the SDK without it being loaded at
    # import time (the autouse mock in conftest replaces it).
    from anthropic import AsyncAnthropic

    settings = get_settings()
    if not settings.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set; cannot triage IPs")

    client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    model = settings.log_agent_model

    response = await client.messages.create(
        model=model,
        max_tokens=2048,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        tools=[_RECORD_SUGGESTIONS_TOOL],
        tool_choice={"type": "tool", "name": "record_suggestions"},
        messages=[{"role": "user", "content": _format_user_message(grouped)}],
    )

    # Parse tool_use block.
    suggestions: list[Suggestion] = []
    by_ip = {s.ip: s for s in grouped}
    for block in response.content:
        if getattr(block, "type", None) != "tool_use":
            continue
        items = block.input.get("suggestions", []) if isinstance(block.input, dict) else []
        for item in items:
            ip = item.get("ip", "").strip()
            if not ip:
                continue
            evidence = by_ip[ip].sample_lines if ip in by_ip else []
            suggestions.append(
                Suggestion(
                    target=ip,
                    action=item.get("action", "ignore"),
                    confidence=int(item.get("confidence", 0)),
                    reason=item.get("reason", ""),
                    evidence=evidence,
                )
            )
        break  # one tool_use block is all we expect

    usage = response.usage
    token_usage = TokenUsage(
        input_tokens=getattr(usage, "input_tokens", 0) or 0,
        output_tokens=getattr(usage, "output_tokens", 0) or 0,
        cache_creation_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
    )
    logger.info(
        "Triage complete: %d suggestions, in=%d out=%d cache_w=%d cache_r=%d cost=$%.4f",
        len(suggestions),
        token_usage.input_tokens,
        token_usage.output_tokens,
        token_usage.cache_creation_tokens,
        token_usage.cache_read_tokens,
        token_usage.cost_usd,
    )
    return suggestions, token_usage, model
