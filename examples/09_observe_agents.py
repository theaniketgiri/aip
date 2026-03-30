"""
AIP @observe — Lightweight Agent Observability Demo

This example demonstrates ALL @observe features:
  1. Function observation with passport
  2. Class-level observation
  3. Instance-level observation (observe_agent)
  4. Error tracking (observe never blocks)
  5. Parameter & result logging
  6. Real-time callbacks
  7. Per-agent stats & export
  8. The upgrade path: @observe → @shield (one-line change)

pip install aip-protocol
python examples/09_observe_agents.py
"""

import json
import time

from aip_protocol import (
    passport,
    observe,
    observe_agent,
    ObservationStore,
    get_observation_store,
)
from aip_protocol.observe import ObservationEvent


def separator(title: str) -> None:
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}\n")


if __name__ == "__main__":

    # Use a fresh store so we track everything cleanly
    store = ObservationStore()

    # ═══════════════════════════════════════════════════════════
    # 1. FUNCTION OBSERVATION — The simplest use case
    # ═══════════════════════════════════════════════════════════
    separator("1. FUNCTION OBSERVATION")

    # Create an agent identity — this gives the function a DID
    payment_agent = passport(name="payment-bot", domain="acme.com")
    print(f"Agent DID: {payment_agent.agent_id}")

    @observe(payment_agent, store=store, log_result=True)
    def process_payment(to: str, amount: float, currency: str = "USD"):
        """Simulate processing a payment."""
        time.sleep(0.005)  # simulate latency
        return {"status": "processed", "to": to, "amount": amount, "currency": currency}

    # Make some calls — they all execute normally
    result1 = process_payment("vendor-a", 150.00)
    result2 = process_payment("vendor-b", 320.50, currency="EUR")
    result3 = process_payment("vendor-c", 75.00)

    print(f"Payment 1: {result1}")
    print(f"Payment 2: {result2}")
    print(f"Payment 3: {result3}")
    print(f"\n✅ All payments processed — @observe logged them silently")

    # ═══════════════════════════════════════════════════════════
    # 2. CLASS OBSERVATION — Observe an entire agent class
    # ═══════════════════════════════════════════════════════════
    separator("2. CLASS OBSERVATION")

    analyst_agent = passport(name="analyst-bot", domain="acme.com")
    print(f"Agent DID: {analyst_agent.agent_id}")

    @observe(analyst_agent, store=store)
    class DataAnalyst:
        """A multi-capability agent with read, analyze, and report actions."""

        def read_data(self, source: str):
            time.sleep(0.002)
            return f"Read 1,247 rows from {source}"

        def analyze(self, query: str):
            time.sleep(0.003)
            return f"Analysis complete: {query}"

        def generate_report(self, title: str):
            time.sleep(0.001)
            return f"Report '{title}' generated"

        def _internal_helper(self):
            """This private method is NOT observed."""
            return "internal"

    analyst = DataAnalyst()
    print(analyst.read_data("sales_db"))
    print(analyst.analyze("Q4 revenue trends"))
    print(analyst.generate_report("Quarterly Review"))
    analyst._internal_helper()  # not observed

    print(f"\n✅ 3 public methods observed, private methods ignored")

    # ═══════════════════════════════════════════════════════════
    # 3. INSTANCE OBSERVATION — Observe an existing object
    # ═══════════════════════════════════════════════════════════
    separator("3. INSTANCE OBSERVATION")

    class NotificationService:
        def send_email(self, to: str, subject: str):
            return f"Email sent to {to}: {subject}"

        def send_slack(self, channel: str, message: str):
            return f"Slack #{channel}: {message}"

        def send_webhook(self, url: str, payload: dict):
            return f"Webhook → {url}"

    # Create the service normally, THEN observe it
    notifier = NotificationService()
    notifier_agent = passport(name="notifier-bot", domain="acme.com")
    notifier = observe_agent(notifier, agent=notifier_agent, store=store)

    print(f"Agent DID: {notifier_agent.agent_id}")
    print(notifier.send_email("team@acme.com", "Daily Report"))
    print(notifier.send_slack("alerts", "System healthy"))
    print(notifier.send_webhook("https://hooks.acme.com/alerts", {"status": "ok"}))

    print(f"\n✅ Existing instance observed — zero code changes to the class")

    # ═══════════════════════════════════════════════════════════
    # 4. ERROR TRACKING — Observe NEVER blocks execution
    # ═══════════════════════════════════════════════════════════
    separator("4. ERROR TRACKING")

    error_agent = passport(name="risky-bot", domain="acme.com")

    @observe(error_agent, store=store)
    def risky_operation(x: int):
        if x == 0:
            raise ZeroDivisionError("Cannot divide by zero")
        return 100 / x

    # Successful calls
    print(f"risky_operation(5) = {risky_operation(5)}")
    print(f"risky_operation(2) = {risky_operation(2)}")

    # Failing call — observe logs the error but NEVER blocks
    try:
        risky_operation(0)
    except ZeroDivisionError as e:
        print(f"Caught error: {e}")
        print(f"⚠️  Error was caught AND logged by @observe")

    print(f"\n✅ @observe never prevents execution — errors are logged, not swallowed")

    # ═══════════════════════════════════════════════════════════
    # 5. REAL-TIME CALLBACKS — Stream events as they happen
    # ═══════════════════════════════════════════════════════════
    separator("5. REAL-TIME CALLBACKS")

    callback_agent = passport(name="callback-bot", domain="acme.com")

    # Register a callback for real-time monitoring
    def on_agent_action(event: ObservationEvent):
        status = "✓" if event.success else "✗"
        print(f"  📡 [{status}] {event.agent_name} → {event.action} ({event.latency_ms}ms)")

    store.on_event(on_agent_action)

    @observe(callback_agent, store=store)
    def monitored_action(task: str):
        time.sleep(0.001)
        return f"Completed: {task}"

    print("Making calls with real-time callback:")
    monitored_action("fetch_data")
    monitored_action("process_batch")
    monitored_action("sync_results")

    print(f"\n✅ Callbacks fire in real-time — perfect for dashboard streaming")

    # ═══════════════════════════════════════════════════════════
    # 6. PER-AGENT STATS — Who did what, how often
    # ═══════════════════════════════════════════════════════════
    separator("6. PER-AGENT STATS")

    # Stats for the payment agent
    payment_stats = store.stats(payment_agent.agent_id)
    print(f"Payment Bot Stats:")
    print(f"  Total calls:  {payment_stats['total']}")
    print(f"  Successes:    {payment_stats['success']}")
    print(f"  Errors:       {payment_stats['errors']}")

    # Stats for the error agent
    error_stats = store.stats(error_agent.agent_id)
    print(f"\nRisky Bot Stats:")
    print(f"  Total calls:  {error_stats['total']}")
    print(f"  Successes:    {error_stats['success']}")
    print(f"  Errors:       {error_stats['errors']}")

    # Global stats
    global_stats = store.stats()
    print(f"\nGlobal Stats:")
    print(f"  Total events: {global_stats['total_events']}")
    print(f"  Active agents: {len(global_stats['agents'])}")

    # ═══════════════════════════════════════════════════════════
    # 7. EXPORT — JSON export for dashboard / analysis
    # ═══════════════════════════════════════════════════════════
    separator("7. JSON EXPORT")

    # Export all events
    exported = json.loads(store.export_json())
    print(f"Exported {len(exported)} events")
    print(f"\nSample event:")
    print(json.dumps(exported[0], indent=2))

    # Filter events for a specific agent
    payment_events = store.events_for_agent(payment_agent.agent_id)
    print(f"\nPayment Bot events: {len(payment_events)}")
    for event in payment_events:
        print(f"  → {event.action}({event.parameters}) [{event.latency_ms}ms]")

    # ═══════════════════════════════════════════════════════════
    # 8. UPGRADE PATH — @observe → @shield (one-line change)
    # ═══════════════════════════════════════════════════════════
    separator("8. UPGRADE PATH: @observe → @shield")

    print("Current code (observe — no enforcement):")
    print("""
    @observe(agent)
    def process_payment(to: str, amount: float):
        return stripe.charge(to, amount)
    """)

    print("After one-line change (shield — full enforcement):")
    print("""
    @shield(actions=["process_payment"], limit=500)
    def process_payment(to: str, amount: float):
        return stripe.charge(to, amount)
    """)

    # Prove it works — the same passport works with both
    from aip_protocol import protect

    upgrade_agent = passport(
        name="upgrade-bot", domain="acme.com",
        actions=["safe_transfer"], limit=100,
    )

    def safe_transfer(amount: float):
        return f"Transferred ${amount}"

    # Shield it with the SAME passport from observe
    shielded = protect(safe_transfer, passport=upgrade_agent)

    print("Shield with same passport:")
    print(f"  safe_transfer(50)  → {shielded(amount=50)}")
    try:
        shielded(amount=500)
    except Exception as e:
        print(f"  safe_transfer(500) → ❌ {e}")

    print(f"\n✅ Same passport, zero architecture change. Just swap the decorator.")

    # ═══════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════
    separator("SUMMARY")

    final_stats = store.stats()
    print(f"Total events recorded: {final_stats['total_events']}")
    print(f"Agents observed:       {len(final_stats['agents'])}")
    print()
    for agent_id, stats in final_stats['agents'].items():
        name = agent_id.split(":")[-1]
        success_rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
        print(f"  {name:20s} │ {stats['total']:3d} calls │ {success_rate:.0f}% success")

    print(f"\n{'═' * 60}")
    print(f"  AIP @observe — Identity + Visibility. Free. Always.")
    print(f"  When you need enforcement: @observe → @shield")
    print(f"{'═' * 60}")
