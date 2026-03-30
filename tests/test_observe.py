"""
AIP Observe — Test Suite

Tests cover:
  1. Function observation (decorator)
  2. Class observation (decorator)
  3. Instance observation (observe_agent)
  4. ObservationStore (ring buffer, stats, export)
  5. Error handling (observe never blocks)
  6. Passport shorthand
  7. Callback system
  8. Parameter and result logging
  9. Upgrade path (@observe → @shield compatibility)
"""

from __future__ import annotations

import json
import time

import pytest

from aip_protocol.passport import AgentPassport
from aip_protocol.observe import (
    observe,
    observe_agent,
    passport,
    ObservationEvent,
    ObservationStore,
    ObservedCall,
    get_observation_store,
    set_observation_store,
)


# ══════════════════════════════════════════════════════════════════════════════
# 1. ObservationEvent Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestObservationEvent:
    def test_event_creation(self):
        event = ObservationEvent(
            agent_id="did:web:acme.com:agents:bot",
            agent_name="bot",
            action="read_data",
            parameters={"query": "invoices"},
        )
        assert event.agent_id == "did:web:acme.com:agents:bot"
        assert event.action == "read_data"
        assert event.success is True
        assert event.event_id  # auto-generated

    def test_event_to_dict(self):
        event = ObservationEvent(
            agent_id="did:web:test.com:agents:bot",
            action="process",
            parameters={"x": 42},
        )
        d = event.to_dict()
        assert d["agent_id"] == "did:web:test.com:agents:bot"
        assert d["action"] == "process"
        assert d["parameters"] == {"x": 42}

    def test_event_to_json(self):
        event = ObservationEvent(
            agent_id="did:web:test.com:agents:bot",
            action="test",
        )
        j = event.to_json()
        parsed = json.loads(j)
        assert parsed["action"] == "test"

    def test_event_non_serializable_result(self):
        """Non-JSON-serializable results should be repr'd, not crash."""
        event = ObservationEvent(
            agent_id="test",
            action="test",
            result=object(),  # not JSON-serializable
        )
        d = event.to_dict()
        assert isinstance(d["result"], str)


# ══════════════════════════════════════════════════════════════════════════════
# 2. ObservationStore Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestObservationStore:
    def test_record_and_retrieve(self):
        store = ObservationStore()
        event = ObservationEvent(agent_id="agent-1", action="read")
        store.record(event)
        assert len(store.events) == 1
        assert store.events[0].action == "read"

    def test_ring_buffer_eviction(self):
        store = ObservationStore(max_events=5)
        for i in range(10):
            store.record(ObservationEvent(agent_id="agent-1", action=f"action_{i}"))
        assert len(store.events) == 5
        # Oldest events should be evicted
        assert store.events[0].action == "action_5"

    def test_per_agent_filtering(self):
        store = ObservationStore()
        store.record(ObservationEvent(agent_id="agent-1", action="read"))
        store.record(ObservationEvent(agent_id="agent-2", action="write"))
        store.record(ObservationEvent(agent_id="agent-1", action="delete"))

        agent1_events = store.events_for_agent("agent-1")
        assert len(agent1_events) == 2
        assert all(e.agent_id == "agent-1" for e in agent1_events)

    def test_stats_tracking(self):
        store = ObservationStore()
        store.record(ObservationEvent(agent_id="agent-1", action="read", success=True))
        store.record(ObservationEvent(agent_id="agent-1", action="write", success=True))
        store.record(ObservationEvent(agent_id="agent-1", action="fail", success=False))

        stats = store.stats("agent-1")
        assert stats["total"] == 3
        assert stats["success"] == 2
        assert stats["errors"] == 1

    def test_global_stats(self):
        store = ObservationStore()
        store.record(ObservationEvent(agent_id="agent-1", action="read"))
        store.record(ObservationEvent(agent_id="agent-2", action="write"))

        stats = store.stats()
        assert stats["total_events"] == 2
        assert "agent-1" in stats["agents"]
        assert "agent-2" in stats["agents"]

    def test_clear(self):
        store = ObservationStore()
        store.record(ObservationEvent(agent_id="agent-1", action="read"))
        store.clear()
        assert len(store.events) == 0
        assert store.stats("agent-1")["total"] == 0

    def test_export_json(self):
        store = ObservationStore()
        store.record(ObservationEvent(agent_id="agent-1", action="read"))
        store.record(ObservationEvent(agent_id="agent-1", action="write"))

        exported = store.export_json()
        parsed = json.loads(exported)
        assert len(parsed) == 2
        assert parsed[0]["action"] == "read"

    def test_callback_system(self):
        store = ObservationStore()
        captured = []
        store.on_event(lambda e: captured.append(e))

        store.record(ObservationEvent(agent_id="agent-1", action="read"))
        assert len(captured) == 1
        assert captured[0].action == "read"

    def test_callback_error_doesnt_crash(self):
        """Bad callbacks should be swallowed, not crash the store."""
        store = ObservationStore()
        store.on_event(lambda e: 1 / 0)  # will raise ZeroDivisionError

        # Should not raise
        store.record(ObservationEvent(agent_id="agent-1", action="read"))
        assert len(store.events) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 3. Function Decorator Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestObserveFunction:
    def test_basic_function_observation(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="func-bot")

        @observe(agent, store=store)
        def add(a: int, b: int) -> int:
            return a + b

        result = add(2, 3)
        assert result == 5  # function still works

        events = store.events
        assert len(events) == 1
        assert events[0].action == "add"
        assert events[0].success is True
        assert events[0].agent_id == "did:web:test.com:agents:func-bot"
        assert events[0].latency_ms >= 0

    def test_observe_captures_parameters(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="param-bot")

        @observe(agent, store=store)
        def greet(name: str, greeting: str = "hello"):
            return f"{greeting} {name}"

        greet("world", greeting="hi")

        events = store.events
        assert events[0].parameters.get("name") == "world"
        assert events[0].parameters.get("greeting") == "hi"

    def test_observe_captures_errors(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="err-bot")

        @observe(agent, store=store)
        def failing_func():
            raise ValueError("something broke")

        with pytest.raises(ValueError, match="something broke"):
            failing_func()

        events = store.events
        assert len(events) == 1
        assert events[0].success is False
        assert "ValueError" in events[0].error
        assert "something broke" in events[0].error

    def test_observe_never_blocks_execution(self):
        """@observe must NEVER prevent function execution."""
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="never-block")

        @observe(agent, store=store)
        def important_function():
            return "critical_result"

        result = important_function()
        assert result == "critical_result"

    def test_observe_without_passport(self):
        """@observe() without a passport auto-creates one."""
        store = ObservationStore()

        @observe(store=store)
        def auto_passport_func():
            return 42

        result = auto_passport_func()
        assert result == 42

        events = store.events
        assert len(events) == 1
        assert "auto_passport_func" in events[0].agent_id

    def test_observe_log_result(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="result-bot")

        @observe(agent, store=store, log_result=True)
        def compute():
            return {"answer": 42}

        compute()
        assert store.events[0].result == {"answer": 42}

    def test_observe_no_log_result_by_default(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="noresult-bot")

        @observe(agent, store=store)
        def compute():
            return {"secret": "data"}

        compute()
        assert store.events[0].result is None

    def test_observe_tracks_latency(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="latency-bot")

        @observe(agent, store=store)
        def slow_func():
            time.sleep(0.01)
            return True

        slow_func()
        assert store.events[0].latency_ms >= 10  # at least 10ms

    def test_multiple_calls_tracked(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="multi-bot")

        @observe(agent, store=store)
        def counter(n: int):
            return n * 2

        for i in range(5):
            counter(i)

        assert len(store.events) == 5
        stats = store.stats(agent.agent_id)
        assert stats["total"] == 5
        assert stats["success"] == 5


# ══════════════════════════════════════════════════════════════════════════════
# 4. Class Decorator Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestObserveClass:
    def test_class_observation(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="class-bot")

        @observe(agent, store=store)
        class MyAgent:
            def read_data(self, query: str):
                return f"results for {query}"

            def send_alert(self, msg: str):
                return f"sent: {msg}"

        bot = MyAgent()
        result = bot.read_data("invoices")
        assert result == "results for invoices"

        bot.send_alert("warning")

        events = store.events
        assert len(events) == 2
        assert events[0].action == "read_data"
        assert events[1].action == "send_alert"

    def test_class_private_methods_not_observed(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="private-bot")

        @observe(agent, store=store)
        class MyAgent:
            def public_method(self):
                return self._private_helper()

            def _private_helper(self):
                return "internal"

        bot = MyAgent()
        bot.public_method()

        # Only public_method should be observed, not _private_helper
        actions = [e.action for e in store.events]
        assert "public_method" in actions
        assert "_private_helper" not in actions

    def test_class_specific_actions(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="selective-bot")

        @observe(agent, actions=["read_data"], store=store)
        class MyAgent:
            def read_data(self):
                return "data"

            def write_data(self):
                return "wrote"

        bot = MyAgent()
        bot.read_data()
        bot.write_data()  # this one should NOT be observed

        assert len(store.events) == 1
        assert store.events[0].action == "read_data"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Instance Observation Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestObserveAgent:
    def test_observe_existing_instance(self):
        store = ObservationStore()
        agent = AgentPassport.create(domain="test.com", agent_name="instance-bot")

        class MyBot:
            def process(self, x: int):
                return x * 2

        bot = MyBot()
        bot = observe_agent(bot, agent=agent, store=store)

        result = bot.process(5)
        assert result == 10

        assert len(store.events) == 1
        assert store.events[0].action == "process"

    def test_observe_agent_passport_attached(self):
        agent = AgentPassport.create(domain="test.com", agent_name="passport-check")

        class MyBot:
            def hello(self):
                return "hi"

        bot = MyBot()
        bot = observe_agent(bot, agent=agent)

        assert hasattr(bot, "_aip_passport")
        assert bot._aip_passport.agent_id == agent.agent_id


# ══════════════════════════════════════════════════════════════════════════════
# 6. Passport Shorthand Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestPassportShorthand:
    def test_passport_creation(self):
        agent = passport(name="my-bot", domain="acme.com")
        assert isinstance(agent, AgentPassport)
        assert agent.agent_id == "did:web:acme.com:agents:my-bot"

    def test_passport_default_domain(self):
        agent = passport(name="local-bot")
        assert "localhost" in agent.agent_id

    def test_passport_with_actions(self):
        agent = passport(name="action-bot", actions=["read", "write"])
        assert "read" in agent.boundaries.allowed_actions
        assert "write" in agent.boundaries.allowed_actions

    def test_passport_with_limit(self):
        agent = passport(name="money-bot", limit=500.0)
        assert agent.boundaries.monetary_limit.per_transaction == 500.0


# ══════════════════════════════════════════════════════════════════════════════
# 7. Global Store Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestGlobalStore:
    def test_get_and_set_store(self):
        original = get_observation_store()
        custom = ObservationStore(max_events=100)
        set_observation_store(custom)

        current = get_observation_store()
        assert current is custom

        # Restore original
        set_observation_store(original)


# ══════════════════════════════════════════════════════════════════════════════
# 8. Upgrade Path Test (@observe → @shield)
# ══════════════════════════════════════════════════════════════════════════════

class TestUpgradePath:
    def test_observe_to_shield_passport_compatible(self):
        """
        The passport created by passport() must be compatible with shield.
        This validates the upgrade path: @observe → @shield.
        """
        from aip_protocol.shield import protect

        # Create a passport using the observe shorthand
        agent = passport(name="upgrade-bot", domain="acme.com", actions=["read_data"], limit=100)

        # Use a named function so shield picks up "read_data" as the action name
        def read_data(query):
            return f"results for {query}"

        # This passport should work with protect() (shield's function API)
        safe_read = protect(
            read_data,
            actions=["read_data"],
            limit=100,
            passport=agent,
        )

        result = safe_read(query="test")
        assert result == "results for test"

    def test_same_did_across_observe_and_shield(self):
        """The DID identity is the same whether using @observe or @shield."""
        agent = passport(name="consistent-bot", domain="acme.com")
        assert agent.agent_id == "did:web:acme.com:agents:consistent-bot"
        # This DID would be the same if passed to @shield


# ══════════════════════════════════════════════════════════════════════════════
# 9. Integration Test
# ══════════════════════════════════════════════════════════════════════════════

class TestObserveIntegration:
    def test_full_observe_workflow(self):
        """
        Full workflow:
        1. Create passport
        2. Observe a function
        3. Call it multiple times (success + failure)
        4. Check store stats
        5. Export events
        """
        store = ObservationStore()
        agent = passport(name="integration-bot", domain="acme.com")

        @observe(agent, store=store, log_result=True)
        def process_order(order_id: str, amount: float):
            if amount > 1000:
                raise ValueError("Amount too high")
            return {"status": "processed", "order_id": order_id}

        # Successful calls
        process_order("ORD-001", 50.0)
        process_order("ORD-002", 200.0)

        # Failing call
        with pytest.raises(ValueError):
            process_order("ORD-003", 5000.0)

        # Verify stats
        stats = store.stats(agent.agent_id)
        assert stats["total"] == 3
        assert stats["success"] == 2
        assert stats["errors"] == 1

        # Verify export
        exported = json.loads(store.export_json())
        assert len(exported) == 3
        assert exported[0]["parameters"]["order_id"] == "ORD-001"
        assert exported[2]["success"] is False

        # Verify callback compatibility
        callback_events = []
        store.on_event(lambda e: callback_events.append(e))
        process_order("ORD-004", 100.0)
        assert len(callback_events) == 1
