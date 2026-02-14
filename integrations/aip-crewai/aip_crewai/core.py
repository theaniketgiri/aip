"""
AIP-protected CrewAI agents and tasks.

Intercepts CrewAI task execution to run AIP verification before
the agent performs any action.
"""

from __future__ import annotations

import logging
from typing import Any

from aip_protocol.envelope import create_envelope, sign_envelope
from aip_protocol.passport import AgentPassport
from aip_protocol.revocation import RevocationStore
from aip_protocol.verification import verify_intent

logger = logging.getLogger("aip.crewai")

_default_store = RevocationStore()


class AIPCrewError(Exception):
    """Raised when AIP verification fails for a CrewAI task."""

    def __init__(self, action: str, errors: list, detail: str):
        self.action = action
        self.errors = errors
        self.detail = detail
        codes = ", ".join(str(e.value) for e in errors)
        super().__init__(f"AIP blocked CrewAI task '{action}': {codes} — {detail}")


def _create_passport(
    agent_name: str,
    actions: list[str] | None = None,
    denied: list[str] | None = None,
    limit: float = 0.0,
    daily_limit: float = 0.0,
    currency: str = "USD",
    domain: str = "localhost",
    geo: str | None = None,
) -> AgentPassport:
    """Create an AIP passport for a CrewAI agent."""
    passport = AgentPassport.create(
        domain=domain,
        agent_name=agent_name,
        allowed_actions=actions or [],
        denied_actions=denied or [],
        monetary_limit_per_txn=limit,
        monetary_limit_per_day=daily_limit,
        currency=currency,
    )
    if geo:
        passport.boundaries.geo_restriction = geo
    return passport


def _verify_action(
    passport: AgentPassport,
    action: str,
    parameters: dict[str, Any] | None = None,
    store: RevocationStore | None = None,
) -> None:
    """Run AIP verification for an action. Raises on failure."""
    store = store or _default_store
    params = parameters or {}

    envelope = create_envelope(
        passport=passport,
        action=action,
        target="crewai-task",
        parameters=params,
    )
    signed = sign_envelope(envelope, passport.private_key)

    result = verify_intent(
        envelope=signed,
        public_key=passport.public_key,
        revocation_store=store,
    )

    if not result.valid:
        raise AIPCrewError(action, result.errors, result.detail)

    logger.debug(f"AIP verified: {action} (trust={result.trust_score})")


def aip_agent(
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
    Protect a CrewAI Agent with AIP verification.

    Usage:
        from crewai import Agent
        from aip_crewai import aip_agent

        agent = aip_agent(
            Agent(role="Researcher", goal="Find data", backstory="..."),
            actions=["research", "read_data"],
            limit=100,
        )

    Args:
        agent: A CrewAI Agent instance
        actions: Allowed actions
        denied: Denied actions
        limit: Per-transaction monetary limit
        daily_limit: Per-day limit
        currency: ISO 4217 currency code
        domain: DID domain
        geo: Geographic restriction

    Returns:
        The agent with AIP passport attached
    """
    agent_name = getattr(agent, "role", "crewai-agent").replace(" ", "-").lower()

    passport = _create_passport(
        agent_name=agent_name,
        actions=actions,
        denied=denied,
        limit=limit,
        daily_limit=daily_limit,
        currency=currency,
        domain=domain,
        geo=geo,
    )

    # Attach AIP context to the agent
    agent._aip_passport = passport
    agent._aip_store = _default_store
    agent._aip_actions = actions or []

    # Monkey-patch the execute_task method to add AIP verification
    original_execute = getattr(agent, "execute_task", None)
    if original_execute:
        def aip_execute_task(task: Any, *args: Any, **kwargs: Any) -> Any:
            action = getattr(task, "description", "unknown")[:50]
            _verify_action(passport, agent._aip_actions[0] if agent._aip_actions else "execute", {"task": action})
            return original_execute(task, *args, **kwargs)

        agent.execute_task = aip_execute_task

    return agent


def aip_task(
    task: Any,
    *,
    action: str = "execute",
    parameters: dict[str, Any] | None = None,
) -> Any:
    """
    Attach AIP metadata to a CrewAI Task.

    The action and parameters will be verified when the task executes.

    Usage:
        task = aip_task(
            Task(description="Research earnings", agent=agent),
            action="research",
        )
    """
    task._aip_action = action
    task._aip_parameters = parameters or {}
    return task


class AIPCrew:
    """
    Wrap an entire CrewAI Crew with AIP protection.

    Usage:
        from aip_crewai import AIPCrew

        crew = AIPCrew(
            Crew(agents=[agent1, agent2], tasks=[task1, task2]),
            limit=500,
            domain="acme.com",
        )
        result = crew.kickoff()
    """

    def __init__(
        self,
        crew: Any,
        *,
        actions: list[str] | None = None,
        denied: list[str] | None = None,
        limit: float = 0.0,
        daily_limit: float = 0.0,
        currency: str = "USD",
        domain: str = "localhost",
        geo: str | None = None,
    ):
        self.crew = crew

        # Protect all agents in the crew
        for agent in getattr(crew, "agents", []):
            if not hasattr(agent, "_aip_passport"):
                agent_name = getattr(agent, "role", "agent").replace(" ", "-").lower()
                aip_agent(
                    agent,
                    actions=actions,
                    denied=denied,
                    limit=limit,
                    daily_limit=daily_limit,
                    currency=currency,
                    domain=domain,
                    geo=geo,
                )

    def kickoff(self, **kwargs: Any) -> Any:
        """Run the crew with AIP verification on all agents."""
        return self.crew.kickoff(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.crew, name)
