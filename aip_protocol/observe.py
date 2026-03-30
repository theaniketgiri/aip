"""
AIP Observe — Lightweight observability for AI agents.

Usage:
    from aip_protocol import observe, passport

    # Observe a function — 1 line
    agent = passport(name="payment-bot", domain="acme.com")

    @observe(agent)
    def process_payment(to: str, amount: float):
        return stripe.charge(to, amount)

    # Logs: agent DID, action, parameters, timestamp, result, latency
    # Zero enforcement. Zero overhead. Full visibility.

    # --- When you need enforcement, change ONE decorator: ---
    # @shield(actions=["process_payment"], limit=500)

This module is the free-tier growth engine for AIP.
Every @observe call embeds a DID identity into the agent's stack.
When security becomes a priority, @observe → @shield is a one-line change.
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

from aip_protocol.passport import AgentPassport

logger = logging.getLogger("aip.observe")

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Observation Event
# ---------------------------------------------------------------------------

@dataclass
class ObservationEvent:
    """A single observed agent action — structured, queryable, exportable."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    agent_id: str = ""
    agent_name: str = ""
    action: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    success: bool = True
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    latency_ms: float = 0.0
    caller: str = ""  # file:line where the call originated

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict (safe for JSON/dashboard)."""
        d = asdict(self)
        # Sanitize result to string if it's not JSON-serializable
        try:
            json.dumps(d["result"])
        except (TypeError, ValueError):
            d["result"] = repr(d["result"])
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# ---------------------------------------------------------------------------
# Observation Store — In-memory ring buffer with export
# ---------------------------------------------------------------------------

class ObservationStore:
    """
    Thread-safe in-memory store for observation events.

    Defaults to 10,000 events (ring buffer). When full, oldest events
    are evicted. This is intentionally lightweight — NOT a database.

    For persistent storage, export to the Korven dashboard.
    """

    def __init__(self, max_events: int = 10_000):
        self._events: deque[ObservationEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[ObservationEvent], None]] = []
        # Per-agent counters for quick stats
        self._agent_stats: dict[str, dict[str, int]] = {}

    def record(self, event: ObservationEvent) -> None:
        """Record an observation event."""
        with self._lock:
            self._events.append(event)

            # Update stats
            agent_id = event.agent_id
            if agent_id not in self._agent_stats:
                self._agent_stats[agent_id] = {
                    "total": 0, "success": 0, "errors": 0,
                }
            stats = self._agent_stats[agent_id]
            stats["total"] += 1
            if event.success:
                stats["success"] += 1
            else:
                stats["errors"] += 1

        # Fire callbacks outside lock
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.warning(f"Observe callback error: {e}")

    def on_event(self, callback: Callable[[ObservationEvent], None]) -> None:
        """Register a callback for every observation event."""
        self._callbacks.append(callback)

    @property
    def events(self) -> list[ObservationEvent]:
        """Get all events (newest last)."""
        with self._lock:
            return list(self._events)

    def events_for_agent(self, agent_id: str) -> list[ObservationEvent]:
        """Get events for a specific agent."""
        with self._lock:
            return [e for e in self._events if e.agent_id == agent_id]

    def stats(self, agent_id: str | None = None) -> dict[str, Any]:
        """Get observation stats, optionally filtered by agent."""
        with self._lock:
            if agent_id:
                return dict(self._agent_stats.get(agent_id, {
                    "total": 0, "success": 0, "errors": 0,
                }))
            return {
                "total_events": len(self._events),
                "agents": dict(self._agent_stats),
            }

    def clear(self) -> None:
        """Clear all events and stats."""
        with self._lock:
            self._events.clear()
            self._agent_stats.clear()

    def export_json(self) -> str:
        """Export all events as JSON array."""
        return json.dumps([e.to_dict() for e in self.events], default=str)


# ---------------------------------------------------------------------------
# Module-level default store
# ---------------------------------------------------------------------------

_default_store = ObservationStore()


def get_observation_store() -> ObservationStore:
    """Get the global observation store."""
    return _default_store


def set_observation_store(store: ObservationStore) -> None:
    """Replace the global observation store."""
    global _default_store
    _default_store = store


# ---------------------------------------------------------------------------
# Helper: auto-create passport from shorthand
# ---------------------------------------------------------------------------

def passport(
    name: str,
    domain: str = "localhost",
    **kwargs: Any,
) -> AgentPassport:
    """
    Create a lightweight agent passport for observation.

    This is the shorthand for giving an agent a DID identity:
        agent = passport(name="my-bot", domain="acme.com")

    The passport embeds a cryptographic identity (DID) that persists
    across @observe and upgrades seamlessly to @shield.
    """
    return AgentPassport.create(
        domain=domain,
        agent_name=name,
        allowed_actions=kwargs.get("actions", []),
        denied_actions=kwargs.get("denied", []),
        monetary_limit_per_txn=kwargs.get("limit", 0.0),
        monetary_limit_per_day=kwargs.get("daily_limit", 0.0),
        currency=kwargs.get("currency", "USD"),
    )


# ---------------------------------------------------------------------------
# Core: @observe decorator
# ---------------------------------------------------------------------------

class ObservedCall:
    """
    Wraps a function with observation logging.

    Every call is:
    1. Logged with structured metadata (agent DID, action, params)
    2. Timed for latency tracking
    3. Result/error captured
    4. Stored in the observation store

    Zero enforcement. The function ALWAYS executes.
    """

    def __init__(
        self,
        func: Callable[..., Any],
        *,
        agent_passport: AgentPassport,
        action_name: str | None = None,
        store: ObservationStore | None = None,
        log_params: bool = True,
        log_result: bool = False,
    ):
        self._func = func
        self._passport = agent_passport
        self._action = action_name or getattr(func, "__name__", "unknown")
        self._store = store or _default_store
        self._log_params = log_params
        self._log_result = log_result
        functools.update_wrapper(self, func)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # Capture caller info
        frame = inspect.currentframe()
        caller = ""
        if frame and frame.f_back:
            caller = f"{frame.f_back.f_code.co_filename}:{frame.f_back.f_lineno}"

        # Build parameters dict
        params = {}
        if self._log_params:
            params = dict(kwargs)
            if args:
                sig = inspect.signature(self._func)
                param_names = list(sig.parameters.keys())
                for i, arg in enumerate(args):
                    key = param_names[i] if i < len(param_names) else f"arg_{i}"
                    # Skip 'self' for bound methods
                    if key == "self":
                        continue
                    try:
                        json.dumps(arg)
                        params[key] = arg
                    except (TypeError, ValueError):
                        params[key] = repr(arg)

        # Execute — ALWAYS runs, observe never blocks
        start = time.perf_counter()
        event = ObservationEvent(
            agent_id=self._passport.agent_id,
            agent_name=self._passport.identity.id.split(":")[-1],
            action=self._action,
            parameters=params,
            caller=caller,
        )

        try:
            result = self._func(*args, **kwargs)
            event.success = True
            if self._log_result:
                event.result = result
            elapsed = (time.perf_counter() - start) * 1000
            event.latency_ms = round(elapsed, 2)

            logger.debug(
                f"[observe] {self._passport.agent_id} → {self._action} "
                f"({event.latency_ms}ms) ✓"
            )
            self._store.record(event)
            return result

        except Exception as exc:
            event.success = False
            event.error = f"{type(exc).__name__}: {exc}"
            elapsed = (time.perf_counter() - start) * 1000
            event.latency_ms = round(elapsed, 2)

            logger.debug(
                f"[observe] {self._passport.agent_id} → {self._action} "
                f"({event.latency_ms}ms) ✗ {event.error}"
            )
            self._store.record(event)
            raise  # Always re-raise — observe never swallows errors


def observe(
    agent: AgentPassport | None = None,
    *,
    actions: list[str] | None = None,
    store: ObservationStore | None = None,
    log_params: bool = True,
    log_result: bool = False,
    domain: str = "localhost",
    agent_name: str | None = None,
) -> Callable:
    """
    Observe an agent's actions — lightweight, zero-enforcement logging.

    Can be used as:
        # 1. Function decorator with passport
        agent = passport(name="my-bot", domain="acme.com")

        @observe(agent)
        def process_payment(to: str, amount: float):
            return stripe.charge(to, amount)

        # 2. Function decorator without passport (auto-creates one)
        @observe()
        def my_function():
            ...

        # 3. Class decorator — observes all public methods
        @observe(agent)
        class MyAgent:
            def read_data(self, query): ...
            def send_alert(self, msg): ...

    Args:
        agent: AgentPassport for identity. Auto-created if None.
        actions: List of actions to observe (class mode). None = all public methods.
        store: ObservationStore to use. Uses global default if None.
        log_params: Whether to log function parameters (default: True).
        log_result: Whether to log return values (default: False, for privacy).
        domain: Domain for auto-created passport.
        agent_name: Name for auto-created passport.

    Returns:
        Decorated function or class with observation logging.
    """
    resolved_store = store or _default_store

    def decorator(target: Any) -> Any:
        nonlocal agent

        if isinstance(target, type):
            # --- Class decorator ---
            return _observe_class(
                target,
                agent=agent,
                actions=actions,
                store=resolved_store,
                log_params=log_params,
                log_result=log_result,
                domain=domain,
                agent_name=agent_name,
            )
        else:
            # --- Function decorator ---
            if agent is None:
                resolved_agent = AgentPassport.create(
                    domain=domain,
                    agent_name=agent_name or getattr(target, "__name__", "observed-agent"),
                )
            else:
                resolved_agent = agent

            return ObservedCall(
                target,
                agent_passport=resolved_agent,
                store=resolved_store,
                log_params=log_params,
                log_result=log_result,
            )

    # Support both @observe(agent) and @observe() syntax
    if agent is not None and callable(agent) and not isinstance(agent, AgentPassport):
        # Called as @observe (no parens, no agent) — agent is actually the function
        func = agent
        agent = AgentPassport.create(
            domain=domain,
            agent_name=getattr(func, "__name__", "observed-agent"),
        )
        return ObservedCall(
            func,
            agent_passport=agent,
            store=resolved_store,
            log_params=log_params,
            log_result=log_result,
        )

    return decorator


def _observe_class(
    cls: type,
    *,
    agent: AgentPassport | None,
    actions: list[str] | None,
    store: ObservationStore,
    log_params: bool,
    log_result: bool,
    domain: str,
    agent_name: str | None,
) -> type:
    """Wrap all public methods of a class with observation."""
    original_init = cls.__init__

    def new_init(self, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)

        # Create or reuse passport
        resolved_agent = agent or AgentPassport.create(
            domain=domain,
            agent_name=agent_name or cls.__name__,
        )

        self._aip_passport = resolved_agent
        self._aip_observe_store = store

        # Determine which methods to observe
        target_actions = actions or [
            name for name in dir(cls)
            if not name.startswith("_") and callable(getattr(cls, name))
        ]

        # Wrap each method
        for method_name in target_actions:
            method = getattr(self, method_name, None)
            if method and callable(method):
                observed = ObservedCall(
                    method,
                    agent_passport=resolved_agent,
                    action_name=method_name,
                    store=store,
                    log_params=log_params,
                    log_result=log_result,
                )
                setattr(self, method_name, observed)

    cls.__init__ = new_init
    return cls


def observe_agent(
    agent_instance: Any,
    *,
    agent: AgentPassport | None = None,
    actions: list[str] | None = None,
    store: ObservationStore | None = None,
    log_params: bool = True,
    log_result: bool = False,
    domain: str = "localhost",
    agent_name: str | None = None,
) -> Any:
    """
    Observe an existing agent instance — THE one-liner for instances.

    Usage:
        from aip_protocol import observe_agent, passport

        bot = MyBot()
        bot = observe_agent(bot, agent=passport(name="my-bot"))

        # Now every method call is logged with structured AIP identity.
        # When you need enforcement: change to protect_agent()

    Args:
        agent_instance: Any object. All public methods will be wrapped.
        agent: AgentPassport for identity.
        actions: Methods to observe. None = all public methods.
        store: Observation store. Uses global default if None.
        log_params: Log function parameters.
        log_result: Log return values.
        domain: Domain for auto-created passport.
        agent_name: Name for auto-created passport.

    Returns:
        The same instance with all public methods observed.
    """
    resolved_store = store or _default_store
    resolved_agent = agent or AgentPassport.create(
        domain=domain,
        agent_name=agent_name or type(agent_instance).__name__,
    )

    target_actions = actions or [
        name for name in dir(agent_instance)
        if not name.startswith("_") and callable(getattr(agent_instance, name))
    ]

    agent_instance._aip_passport = resolved_agent
    agent_instance._aip_observe_store = resolved_store

    for method_name in target_actions:
        method = getattr(agent_instance, method_name, None)
        if method and callable(method):
            observed = ObservedCall(
                method,
                agent_passport=resolved_agent,
                action_name=method_name,
                store=resolved_store,
                log_params=log_params,
                log_result=log_result,
            )
            setattr(agent_instance, method_name, observed)

    return agent_instance
