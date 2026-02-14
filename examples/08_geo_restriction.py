"""
AIP Geo Restriction — Restrict agents to specific geographies.

Agents can be restricted to operate only from specific countries.
Any request from outside the allowed geography is blocked.

pip install aip-protocol
python examples/08_geo_restriction.py
"""

from aip_protocol import (
    AgentPassport,
    create_envelope,
    sign_envelope,
    verify_intent,
    RevocationStore,
)


if __name__ == "__main__":
    store = RevocationStore()

    # ── Create a US-only agent ───────────────────────────────────────
    passport = AgentPassport.create(
        domain="us-bank.com",
        agent_name="compliance-bot",
        allowed_actions=["transfer_domestic", "read_account"],
        monetary_limit_per_txn=50000,
    )
    passport.boundaries.geo_restriction = "US"

    print("=== AIP Geo Restriction ===")
    print(f"Agent: {passport.agent_id}")
    print(f"Geo: US only")
    print()

    # ── Request from US → ✅ ─────────────────────────────────────────
    envelope1 = create_envelope(
        passport=passport,
        action="transfer_domestic",
        parameters={"amount": 1000, "to": "savings"},
    )
    signed1 = sign_envelope(envelope1, passport.private_key)
    result1 = verify_intent(
        envelope=signed1,
        public_key=passport.public_key,
        revocation_store=store,
        request_geo="US",
    )
    print(f"From US:     {'✅ Allowed' if result1.valid else '❌ Blocked'}")

    # ── Request from UK → ❌ ─────────────────────────────────────────
    envelope2 = create_envelope(
        passport=passport,
        action="transfer_domestic",
        parameters={"amount": 1000, "to": "savings"},
    )
    signed2 = sign_envelope(envelope2, passport.private_key)
    result2 = verify_intent(
        envelope=signed2,
        public_key=passport.public_key,
        revocation_store=store,
        request_geo="GB",
    )
    print(f"From UK:     {'✅ Allowed' if result2.valid else '❌ BLOCKED'}")
    if result2.errors:
        print(f"  Error: {result2.errors[0].value}")

    # ── Request from Russia → ❌ ─────────────────────────────────────
    envelope3 = create_envelope(
        passport=passport,
        action="read_account",
        parameters={"account": "checking"},
    )
    signed3 = sign_envelope(envelope3, passport.private_key)
    result3 = verify_intent(
        envelope=signed3,
        public_key=passport.public_key,
        revocation_store=store,
        request_geo="RU",
    )
    print(f"From Russia: {'✅ Allowed' if result3.valid else '❌ BLOCKED'}")
    if result3.errors:
        print(f"  Error: {result3.errors[0].value}")

    print()
    print("Geo restriction enforced at the protocol level — not by firewall rules.")
