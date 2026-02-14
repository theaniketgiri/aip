"""
AIP-protected AutoGen agents.

Intercepts AutoGen message sending to verify each message through
the AIP pipeline before delivery.
"""

from __future__ import annotations

import logging
from typing import Any

from aip_protocol.envelope import create_envelope, sign_envelope
from aip_protocol.passport import AgentPassport
from aip_protocol.revocation import RevocationStore
from aip_protocol.verification import verify_intent

logger = logging.getLogger("aip.autogen")

_default_store = RevocationStore()


class AIPAutoGenError(Exception):
    """Raised when AIP verification fails for an AutoGen message."""

    def __init__(self, agent_name: str, action: str, errors: list, detail: str):
        self.agent_name = agent_name
        self.action = action
        self.errors = errors
        self.detail = detail
        codes = ", ".join(str(e.value) for e in errors)
        super().__init__(
            f"AIP blocked {agent_name} → {action}: {codes} — {detail}"
        )


def _verify(
    passport: AgentPassport,
    action: str,
    parameters: dict[str, Any],
    store: RevocationStore,
) -> None:
    """Run AIP verification. Raises AIPAutoGenError on failure."""
    envelope = create_envelope(
        passport=passport,
        action=action,
        target="autogen-agent",
        parameters=parameters,
    )
    signed = sign_envelope(envelope, passport.private_key)

    result = verify_intent(
        envelope=signed,
        public_key=passport.public_key,
        revocation_store=store,
    )

    if not result.valid:
        raise AIPAutoGenError(
            passport.identity.id, action, result.errors, result.detail
        )


def aip_wrap(
    agent: Any,
    *,
    actions: list[str] | None = None,
    denied: list[str] | None = None,
    limit: float = 0.0,
    daily_limit: float = 0.0,
    currency: str = "USD",
    domain: str = "localhost",
    geo: str | None = None,
) -> Any:
    """
    Wrap an AutoGen agent with AIP verification.

    Every message the agent sends will be verified through AIP before delivery.

    Usage:
        from autogen import AssistantAgent
        from aip_autogen import aip_wrap

        assistant = aip_wrap(
            AssistantAgent("assistant", llm_config={...}),
            actions=["respond", "analyze"],
            limit=500,
        )

    Args:
        agent: An AutoGen agent (AssistantAgent, UserProxyAgent, etc.)
        actions: Allowed actions
        denied: Denied actions
        limit: Per-transaction monetary limit
        daily_limit: Per-day limit
        currency: ISO 4217 currency code
        domain: DID domain
        geo: Geographic restriction

    Returns:
        The agent with AIP verification on send
    """
    agent_name = getattr(agent, "name", "autogen-agent")

    passport = AgentPassport.create(
        domain=domain,
        agent_name=agent_name,
        allowed_actions=actions or ["respond", "request"],
        denied_actions=denied or [],
        monetary_limit_per_txn=limit,
        monetary_limit_per_day=daily_limit,
        currency=currency,
    )
    if geo:
        passport.boundaries.geo_restriction = geo

    agent._aip_passport = passport
    agent._aip_store = _default_store

    # Monkey-patch send method to add AIP verification
    original_send = getattr(agent, "send", None)
    if original_send:
        def aip_send(
            message: Any,
            recipient: Any,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            # Determine action from message content
            action = actions[0] if actions else "respond"
            msg_text = str(message) if not isinstance(message, dict) else message.get("content", "")

            _verify(
                passport,
                action,
                {"message": msg_text[:200], "recipient": getattr(recipient, "name", "unknown")},
                _default_store,
            )

            return original_send(message, recipient, *args, **kwargs)

        agent.send = aip_send

    return agent


class AIPConversation:
    """
    Protect an entire AutoGen multi-agent conversation.

    Usage:
        conv = AIPConversation(
            agents=[assistant, coder, reviewer],
            limit=500,
            domain="acme.com",
        )
    """

    def __init__(
        self,
        agents: list[Any],
        *,
        actions: list[str] | None = None,
        denied: list[str] | None = None,
        limit: float = 0.0,
        daily_limit: float = 0.0,
        currency: str = "USD",
        domain: str = "localhost",
        geo: str | None = None,
    ):
        self.agents = []
        for agent in agents:
            if not hasattr(agent, "_aip_passport"):
                agent = aip_wrap(
                    agent,
                    actions=actions,
                    denied=denied,
                    limit=limit,
                    daily_limit=daily_limit,
                    currency=currency,
                    domain=domain,
                    geo=geo,
                )
            self.agents.append(agent)

    def get_agents(self) -> list[Any]:
        """Get the AIP-protected agents."""
        return self.agents
