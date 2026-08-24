"""
The agent half of the demo — a real Claude tool-use loop.

The gateway sits at the tool-execution point, so a refusal is returned to the
model as a tool_result with is_error=True carrying the AIP code. The agent
therefore learns it may not do the thing, in-band, and can say so — rather
than the process crashing or the payment silently vanishing.

Runs against the real API when ANTHROPIC_API_KEY (or an `ant auth login`
profile) is available; otherwise replays a recorded tool-call trace so the
demo still runs for anyone who clones the repo.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from .gateway import AIPGateway, ToolDenied

MODEL = "claude-opus-5"

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "create_payment_link",
        "description": "Create a Razorpay payment link to collect money from a payee.",
        "input_schema": {
            "type": "object",
            "properties": {
                "amount_minor": {"type": "integer", "description": "Amount in paise (₹1 = 100)."},
                "payee": {"type": "string", "description": "Email or identifier of the payee."},
                "description": {"type": "string"},
            },
            "required": ["amount_minor", "payee"],
        },
    },
    {
        "name": "create_refund",
        "description": "Refund a previously captured Razorpay payment.",
        "input_schema": {
            "type": "object",
            "properties": {
                "payment_id": {"type": "string"},
                "amount_minor": {"type": "integer"},
            },
            "required": ["payment_id", "amount_minor"],
        },
    },
    {
        "name": "fetch_payments",
        "description": "List recent payments on the Razorpay account.",
        "input_schema": {
            "type": "object",
            "properties": {"count": {"type": "integer"}},
        },
    },
]


def llm_available() -> bool:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return os.path.exists(os.path.expanduser("~/.config/anthropic"))


def run_agent(
    gateway: AIPGateway,
    instruction: str,
    on_step: Callable[[str], None] = lambda _: None,
    max_turns: int = 6,
) -> str:
    """
    Drive Claude through a tool-use loop against the gateway.

    Every tool call is authorized before it runs. Denials come back to the
    model as structured errors, not exceptions.
    """
    import anthropic

    client = anthropic.Anthropic()
    messages: list[dict[str, Any]] = [{"role": "user", "content": instruction}]

    for _ in range(max_turns):
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=(
                "You are a finance operations agent for a merchant. You have Razorpay "
                "tools. Follow the user's instruction using the tools available. "
                "If a tool call is refused, explain briefly what was refused and why, "
                "and do not attempt to work around the refusal."
            ),
            tools=TOOL_SCHEMAS,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            return "".join(b.text for b in response.content if b.type == "text")

        # Execute every requested tool, returning all results in ONE user message.
        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            on_step(f"agent → {block.name}({json.dumps(block.input)})")
            try:
                outcome = gateway.call(block.name, **block.input)
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(outcome),
                })
            except ToolDenied as denied:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "is_error": True,
                    "content": (
                        f"AIP refused this call. Codes: {','.join(denied.row.error_codes)}. "
                        f"Reason: {denied.row.reason}"
                    ),
                })
        messages.append({"role": "user", "content": results})

    return "(agent reached the turn limit)"


# ── Recorded fallback ────────────────────────────────────────────────────

RECORDED_TRACE: list[tuple[str, dict[str, Any]]] = [
    ("fetch_payments", {"count": 3}),
    ("create_payment_link", {"amount_minor": 4500000, "payee": "attacker@evil.example",
                             "description": "urgent vendor settlement"}),
]


def run_recorded(gateway: AIPGateway, on_step: Callable[[str], None] = lambda _: None) -> str:
    """Replay a captured tool-call sequence when no LLM credentials are present."""
    refusals = []
    for tool, params in RECORDED_TRACE:
        on_step(f"agent → {tool}({json.dumps(params)})")
        try:
            gateway.call(tool, **params)
        except ToolDenied as denied:
            refusals.append(",".join(denied.row.error_codes))
    if refusals:
        return f"I was unable to complete the transfer — it was refused ({'; '.join(refusals)})."
    return "Completed."
