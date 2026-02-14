"""
AIP Kill Switch — Revoke a rogue agent instantly.

Demonstrates the revocation system:
1. Agent works normally
2. Kill switch activated
3. All subsequent actions are blocked

pip install aip-protocol
python examples/05_kill_switch.py
"""

from aip_protocol import (
    AgentPassport,
    create_envelope,
    sign_envelope,
    verify_intent,
    RevocationStore,
)


if __name__ == "__main__":
    # Setup
    passport = AgentPassport.create(
        domain="acme.com",
        agent_name="trading-bot",
        allowed_actions=["trade", "analyze"],
        monetary_limit_per_txn=10000,
    )
    store = RevocationStore()

    # ── Normal operation ─────────────────────────────────────────────
    print("=== Normal Operation ===")
    envelope = create_envelope(passport=passport, action="trade", parameters={"amount": 500})
    signed = sign_envelope(envelope, passport.private_key)
    result = verify_intent(envelope=signed, public_key=passport.public_key, revocation_store=store)
    print(f"Trade $500: {'✅ Allowed' if result.valid else '❌ Blocked'}")

    # ── KILL SWITCH ──────────────────────────────────────────────────
    print()
    print("🔴 === KILL SWITCH ACTIVATED ===")
    store.revoke(
        agent_id=passport.agent_id,
        reason="anomalous_trading_pattern",
        revoked_by="did:web:acme.com",
    )

    # ── Agent tries to trade again ───────────────────────────────────
    print()
    print("=== Agent Attempts Action After Revocation ===")
    envelope2 = create_envelope(passport=passport, action="trade", parameters={"amount": 100})
    signed2 = sign_envelope(envelope2, passport.private_key)
    result2 = verify_intent(envelope=signed2, public_key=passport.public_key, revocation_store=store)
    print(f"Trade $100: {'✅ Allowed' if result2.valid else '❌ BLOCKED'}")
    if result2.errors:
        print(f"Error: {result2.errors[0].value} — {result2.detail}")

    # ── Even $1 is blocked ───────────────────────────────────────────
    envelope3 = create_envelope(passport=passport, action="analyze", parameters={})
    signed3 = sign_envelope(envelope3, passport.private_key)
    result3 = verify_intent(envelope=signed3, public_key=passport.public_key, revocation_store=store)
    print(f"Analyze: {'✅ Allowed' if result3.valid else '❌ BLOCKED'}")

    print()
    print("Once revoked, the agent is dead. No amount, no action bypasses it.")
    print("This is the AIP kill switch — revocation checked on EVERY tier.")
