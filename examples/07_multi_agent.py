"""
AIP Multi-Agent — Verify agent-to-agent communication.

Two agents communicate, each verifying the other's intent
before accepting messages.

pip install aip-protocol
python examples/07_multi_agent.py
"""

from aip_protocol import (
    AgentPassport,
    create_envelope,
    sign_envelope,
    verify_intent,
    RevocationStore,
)
from aip_protocol.crypto import public_key_to_b64


if __name__ == "__main__":
    store = RevocationStore()

    # ── Create two agents ────────────────────────────────────────────
    buyer = AgentPassport.create(
        domain="buyer-corp.com",
        agent_name="procurement",
        allowed_actions=["request_quote", "approve_payment"],
        monetary_limit_per_txn=10000,
    )

    seller = AgentPassport.create(
        domain="seller-corp.com",
        agent_name="sales",
        allowed_actions=["send_quote", "process_order"],
        monetary_limit_per_txn=50000,
    )

    print("=== AIP Multi-Agent Communication ===")
    print(f"Buyer:  {buyer.agent_id}")
    print(f"Seller: {seller.agent_id}")
    print()

    # ── Buyer requests a quote ───────────────────────────────────────
    print("Step 1: Buyer → Seller (request_quote)")
    envelope1 = create_envelope(
        passport=buyer,
        action="request_quote",
        target=seller.agent_id,
        parameters={"item": "Industrial Widget", "quantity": 100},
        first_contact=True,  # First interaction → Tier 2
    )
    signed1 = sign_envelope(envelope1, buyer.private_key)
    result1 = verify_intent(
        envelope=signed1,
        public_key=buyer.public_key,
        revocation_store=store,
    )
    print(f"  Tier: {result1.tier_used.value}")
    print(f"  Verified: {'✅' if result1.valid else '❌'}")
    print()

    # ── Seller sends quote back ──────────────────────────────────────
    print("Step 2: Seller → Buyer (send_quote)")
    envelope2 = create_envelope(
        passport=seller,
        action="send_quote",
        target=buyer.agent_id,
        parameters={"item": "Industrial Widget", "quantity": 100, "unit_price": 45.00, "total": 4500.00},
    )
    signed2 = sign_envelope(envelope2, seller.private_key)
    result2 = verify_intent(
        envelope=signed2,
        public_key=seller.public_key,
        revocation_store=store,
    )
    print(f"  Tier: {result2.tier_used.value}")
    print(f"  Verified: {'✅' if result2.valid else '❌'}")
    print()

    # ── Buyer approves payment ───────────────────────────────────────
    print("Step 3: Buyer → Seller (approve_payment: $4,500)")
    envelope3 = create_envelope(
        passport=buyer,
        action="approve_payment",
        target=seller.agent_id,
        parameters={"amount": 4500.00, "currency": "USD", "quote_ref": "Q-2026-001"},
    )
    signed3 = sign_envelope(envelope3, buyer.private_key)
    result3 = verify_intent(
        envelope=signed3,
        public_key=buyer.public_key,
        revocation_store=store,
    )
    print(f"  Tier: {result3.tier_used.value}")
    print(f"  Verified: {'✅' if result3.valid else '❌'}")
    print()

    print("All 3 steps verified. Both agents proved their identity and intent")
    print("cryptographically before every action. This is agent-to-agent HTTPS.")
