"""
AIP-protected LangChain tools.

Wraps any LangChain tool with AIP verification so that every invocation
goes through the cryptographic sign → verify → execute pipeline.
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Optional, Type

from langchain_core.tools import BaseTool, StructuredTool, tool
from langchain_core.callbacks import CallbackManagerForToolRun
from pydantic import BaseModel

from aip_protocol.envelope import create_envelope, sign_envelope
from aip_protocol.models import VerificationTier
from aip_protocol.passport import AgentPassport
from aip_protocol.revocation import RevocationStore
from aip_protocol.verification import verify_intent

logger = logging.getLogger("aip.langchain")

_default_store = RevocationStore()


class AIPToolError(Exception):
    """Raised when AIP verification fails for a tool call."""

    def __init__(self, action: str, errors: list, detail: str):
        self.action = action
        self.errors = errors
        self.detail = detail
        codes = ", ".join(str(e.value) for e in errors)
        super().__init__(f"AIP blocked '{action}': {codes} — {detail}")


class AIPTool(BaseTool):
    """
    A LangChain tool that wraps any function with AIP verification.

    Every call to this tool:
    1. Creates an Intent Envelope for the action
    2. Signs it with the agent's Ed25519 key
    3. Verifies through the AIP pipeline
    4. Executes only if verification passes
    """

    name: str = ""
    description: str = ""
    args_schema: Optional[Type[BaseModel]] = None

    # AIP internals (excluded from schema)
    _func: Callable = None
    _passport: AgentPassport = None
    _store: RevocationStore = None
    _on_violation: str = "raise"

    class Config:
        arbitrary_types_allowed = True
        underscore_attrs_are_private = True

    def __init__(
        self,
        func: Callable,
        *,
        passport: AgentPassport,
        store: RevocationStore | None = None,
        on_violation: str = "raise",
        **kwargs: Any,
    ):
        # Extract tool metadata
        tool_name = kwargs.pop("name", getattr(func, "__name__", "unknown"))
        tool_desc = kwargs.pop("description", getattr(func, "__doc__", "") or f"AIP-protected tool: {tool_name}")

        super().__init__(name=tool_name, description=tool_desc, **kwargs)
        self._func = func
        self._passport = passport
        self._store = store or _default_store
        self._on_violation = on_violation

    def _run(
        self,
        *args: Any,
        run_manager: Optional[CallbackManagerForToolRun] = None,
        **kwargs: Any,
    ) -> Any:
        """Run the tool with AIP verification."""
        # Build parameters for the envelope
        params = dict(kwargs)
        if args:
            params["_args"] = list(args)

        # Create + sign envelope
        envelope = create_envelope(
            passport=self._passport,
            action=self.name,
            target="langchain-tool",
            parameters=params,
        )
        signed = sign_envelope(envelope, self._passport.private_key)

        # Verify
        result = verify_intent(
            envelope=signed,
            public_key=self._passport.public_key,
            revocation_store=self._store,
        )

        if not result.valid:
            if self._on_violation == "raise":
                raise AIPToolError(self.name, result.errors, result.detail)
            elif self._on_violation == "return_error":
                codes = ", ".join(str(e.value) for e in result.errors)
                return f"[AIP BLOCKED] {codes}: {result.detail}"
            else:
                logger.warning(f"AIP violation on {self.name}: {result.detail}")
                return None

        # Execute
        return self._func(**kwargs) if not args else self._func(*args, **kwargs)


def aip_tool(
    func: Callable | None = None,
    *,
    actions: list[str] | None = None,
    denied: list[str] | None = None,
    limit: float = 0.0,
    daily_limit: float = 0.0,
    currency: str = "USD",
    domain: str = "localhost",
    agent_name: str | None = None,
    geo: str | None = None,
    on_violation: str = "raise",
    return_direct: bool = False,
) -> Callable:
    """
    Decorator that creates an AIP-protected LangChain tool.

    Usage:
        @aip_tool(limit=500)
        def transfer_funds(amount: float, to: str) -> str:
            '''Transfer funds to a recipient.'''
            return f"Sent ${amount} to {to}"

    Args:
        func: The function to wrap (used when called without arguments)
        actions: Allowed actions (defaults to [func.__name__])
        denied: Denied actions
        limit: Per-transaction monetary limit
        daily_limit: Per-day monetary limit
        currency: ISO 4217 currency code
        domain: DID domain
        agent_name: Agent name
        geo: Geographic restriction (ISO 3166-1 alpha-2)
        on_violation: "raise" | "return_error" | "log"
        return_direct: LangChain return_direct flag

    Returns:
        AIPTool instance compatible with LangChain agents
    """
    def decorator(fn: Callable) -> AIPTool:
        func_name = getattr(fn, "__name__", "unknown")
        action_list = actions or [func_name]

        passport = AgentPassport.create(
            domain=domain,
            agent_name=agent_name or func_name,
            allowed_actions=action_list,
            denied_actions=denied or [],
            monetary_limit_per_txn=limit,
            monetary_limit_per_day=daily_limit,
            currency=currency,
        )
        if geo:
            passport.boundaries.geo_restriction = geo

        return AIPTool(
            fn,
            passport=passport,
            on_violation=on_violation,
            name=func_name,
            description=getattr(fn, "__doc__", "") or f"AIP-protected: {func_name}",
            return_direct=return_direct,
        )

    if func is not None:
        return decorator(func)
    return decorator


class AIPToolkit:
    """
    Wrap multiple existing LangChain tools with AIP protection.

    Usage:
        toolkit = AIPToolkit(limit=500, domain="acme.com")
        protected = toolkit.wrap_tools([tool1, tool2, tool3])
    """

    def __init__(
        self,
        *,
        actions: list[str] | None = None,
        denied: list[str] | None = None,
        limit: float = 0.0,
        daily_limit: float = 0.0,
        currency: str = "USD",
        domain: str = "localhost",
        agent_name: str | None = None,
        geo: str | None = None,
        on_violation: str = "raise",
    ):
        self.actions = actions
        self.denied = denied
        self.limit = limit
        self.daily_limit = daily_limit
        self.currency = currency
        self.domain = domain
        self.agent_name = agent_name
        self.geo = geo
        self.on_violation = on_violation

    def wrap_tool(self, tool: BaseTool) -> AIPTool:
        """Wrap a single LangChain tool with AIP."""
        action_list = self.actions or [tool.name]

        passport = AgentPassport.create(
            domain=self.domain,
            agent_name=self.agent_name or tool.name,
            allowed_actions=action_list,
            denied_actions=self.denied or [],
            monetary_limit_per_txn=self.limit,
            monetary_limit_per_day=self.daily_limit,
            currency=self.currency,
        )
        if self.geo:
            passport.boundaries.geo_restriction = self.geo

        def run_original(**kwargs: Any) -> Any:
            return tool.run(kwargs)

        return AIPTool(
            run_original,
            passport=passport,
            on_violation=self.on_violation,
            name=tool.name,
            description=tool.description,
        )

    def wrap_tools(self, tools: list[BaseTool]) -> list[AIPTool]:
        """Wrap multiple LangChain tools with AIP."""
        return [self.wrap_tool(t) for t in tools]
