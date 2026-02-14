"""
AIP Shield — The one-liner API.

Usage:
    from aip_protocol import protect, shield

    # Protect a function — 1 line
    safe_transfer = protect(transfer_funds, actions=["transfer_funds"], limit=500)
    safe_transfer(amount=45, to="vendor")  # ✅ Passes AIP verification
    safe_transfer(amount=10000, to="vendor")  # ❌ AIP-E202: Monetary limit

    # Protect a class — 1 decorator
    @shield(actions=["read_data", "send_email"], limit=100)
    class MyAgent:
        def read_data(self, query): ...
        def send_email(self, to, body): ...

    agent = MyAgent()
    agent.read_data("invoices")  # ✅ Verified
    agent.delete_records()       # ❌ AIP-E200: Action not allowed

This module exists to make AIP adoption trivially easy.
If your setup takes more than 2 lines, we failed.
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, TypeVar, overload

from aip_protocol.envelope import create_envelope, sign_envelope
from aip_protocol.models import VerificationResult, VerificationTier
from aip_protocol.passport import AgentPassport
from aip_protocol.revocation import RevocationStore
from aip_protocol.verification import verify_intent

logger = logging.getLogger("aip.shield")

F = TypeVar("F", bound=Callable[..., Any])

# Module-level singletons
_default_store = RevocationStore()


class AIPViolation(Exception):
    """Raised when an action violates AIP boundaries."""

    def __init__(self, result: VerificationResult):
        self.result = result
        errors = ", ".join(str(e.value) for e in result.errors)
        super().__init__(f"AIP blocked: {errors} — {result.detail}")


class ProtectedAgent:
    """
    Wraps any callable or object with AIP verification.

    Every call is:
    1. Wrapped in a signed Intent Envelope
    2. Verified through the AIP pipeline
    3. Executed only if verification passes
    """

    def __init__(
        self,
        func: Callable[..., Any],
        *,
        passport: AgentPassport,
        store: RevocationStore,
        action_name: str | None = None,
        tier: VerificationTier = VerificationTier.TIER_1,
        on_violation: str = "raise",  # "raise" | "log" | "silent"
    ):
        self._func = func
        self._passport = passport
        self._store = store
        self._action_name = action_name or getattr(func, "__name__", "unknown_action")
        self._tier = tier
        self._on_violation = on_violation
        functools.update_wrapper(self, func)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # Build parameters from kwargs for the envelope
        params = dict(kwargs)
        if args:
            params["_positional_args"] = list(args)

        # Create + sign envelope
        envelope = create_envelope(
            passport=self._passport,
            action=self._action_name,
            target="self",
            parameters=params,
            tier=self._tier,
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
                raise AIPViolation(result)
            elif self._on_violation == "log":
                logger.warning(f"AIP violation: {result.detail}")
                return None
            else:  # silent
                return None

        # Execute the actual function
        return self._func(*args, **kwargs)


def protect(
    func: Callable[..., Any],
    *,
    actions: list[str] | None = None,
    denied: list[str] | None = None,
    limit: float = 0.0,
    daily_limit: float = 0.0,
    currency: str = "USD",
    domain: str = "localhost",
    agent_name: str | None = None,
    geo: str | None = None,
    tier: VerificationTier = VerificationTier.TIER_1,
    on_violation: str = "raise",
    passport: AgentPassport | None = None,
    store: RevocationStore | None = None,
) -> ProtectedAgent:
    """
    Protect a function with AIP verification. One line.

    Usage:
        from aip_protocol import protect

        safe_pay = protect(pay, actions=["pay"], limit=500)
        safe_pay(amount=50, to="vendor")  # ✅
        safe_pay(amount=5000, to="vendor")  # ❌ AIP-E202

    Args:
        func: The function to protect
        actions: Allowed actions (defaults to [func.__name__])
        denied: Denied actions
        limit: Per-transaction monetary limit
        daily_limit: Per-day monetary limit
        currency: ISO 4217 currency code
        domain: Agent domain for DID
        agent_name: Agent name (auto-generated if None)
        geo: ISO 3166-1 alpha-2 geo restriction
        tier: Verification tier
        on_violation: "raise" | "log" | "silent"
        passport: Pre-built passport (overrides other identity args)
        store: Revocation store (uses default if None)

    Returns:
        ProtectedAgent that verifies before executing
    """
    func_name = getattr(func, "__name__", "unknown_action")
    action_list = actions or [func_name]

    if passport is None:
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

    store = store or _default_store

    return ProtectedAgent(
        func,
        passport=passport,
        store=store,
        action_name=func_name,
        tier=tier,
        on_violation=on_violation,
    )


def shield(
    *,
    actions: list[str] | None = None,
    denied: list[str] | None = None,
    limit: float = 0.0,
    daily_limit: float = 0.0,
    currency: str = "USD",
    domain: str = "localhost",
    agent_name: str | None = None,
    geo: str | None = None,
    tier: VerificationTier = VerificationTier.TIER_1,
    on_violation: str = "raise",
) -> Callable:
    """
    Class decorator — shield an entire agent class with AIP.

    Usage:
        @shield(actions=["read_data", "send_email"], limit=100)
        class MyAgent:
            def read_data(self, query):
                return db.query(query)

            def send_email(self, to, body):
                return smtp.send(to, body)

        agent = MyAgent()
        agent.read_data("invoices")   # ✅ AIP verified
        agent.send_email("x", "y")    # ✅ AIP verified

    All public methods (not starting with _) are wrapped with AIP verification.
    """
    def decorator(cls: type) -> type:
        original_init = cls.__init__

        def new_init(self, *args: Any, **kwargs: Any) -> None:
            original_init(self, *args, **kwargs)

            # Create passport for the class instance
            all_actions = actions or [
                name for name in dir(cls)
                if not name.startswith("_") and callable(getattr(cls, name))
            ]

            passport = AgentPassport.create(
                domain=domain,
                agent_name=agent_name or cls.__name__,
                allowed_actions=all_actions,
                denied_actions=denied or [],
                monetary_limit_per_txn=limit,
                monetary_limit_per_day=daily_limit,
                currency=currency,
            )
            if geo:
                passport.boundaries.geo_restriction = geo

            self._aip_passport = passport
            self._aip_store = _default_store

            # Wrap all public methods
            for name in all_actions:
                method = getattr(self, name, None)
                if method and callable(method):
                    protected = ProtectedAgent(
                        method,
                        passport=passport,
                        store=self._aip_store,
                        action_name=name,
                        tier=tier,
                        on_violation=on_violation,
                    )
                    setattr(self, name, protected)

        cls.__init__ = new_init
        return cls

    return decorator


def protect_agent(
    agent: Any,
    *,
    actions: list[str] | None = None,
    denied: list[str] | None = None,
    limit: float = 0.0,
    daily_limit: float = 0.0,
    currency: str = "USD",
    domain: str = "localhost",
    agent_name: str | None = None,
    geo: str | None = None,
    tier: VerificationTier = VerificationTier.TIER_1,
    on_violation: str = "raise",
) -> Any:
    """
    Protect an existing agent instance with AIP. THE one-liner.

    Usage:
        from aip_protocol import protect_agent

        agent = MyAgent()
        agent = protect_agent(agent, limit=500)

        # Now every method call is AIP-verified
        agent.transfer(amount=50)    # ✅
        agent.transfer(amount=5000)  # ❌ AIP-E202

    Args:
        agent: Any object. All public methods will be wrapped.
        actions: Allowed actions. Defaults to all public methods.
        limit: Per-transaction monetary limit
        denied: Explicitly denied actions
        daily_limit: Per-day limit
        currency: ISO 4217 currency
        domain: DID domain
        agent_name: Agent name
        geo: Geographic restriction
        tier: Verification tier
        on_violation: "raise" | "log" | "silent"

    Returns:
        The same agent instance, with all public methods AIP-protected.
    """
    all_actions = actions or [
        name for name in dir(agent)
        if not name.startswith("_") and callable(getattr(agent, name))
    ]

    passport = AgentPassport.create(
        domain=domain,
        agent_name=agent_name or type(agent).__name__,
        allowed_actions=all_actions,
        denied_actions=denied or [],
        monetary_limit_per_txn=limit,
        monetary_limit_per_day=daily_limit,
        currency=currency,
    )
    if geo:
        passport.boundaries.geo_restriction = geo

    store = _default_store

    agent._aip_passport = passport
    agent._aip_store = store

    for name in all_actions:
        method = getattr(agent, name, None)
        if method and callable(method):
            protected = ProtectedAgent(
                method,
                passport=passport,
                store=store,
                action_name=name,
                tier=tier,
                on_violation=on_violation,
            )
            setattr(agent, name, protected)

    return agent
