"""
AIP Full Pipeline — Passport → Envelope → Sign → Verify.

This example shows the full protocol flow for power users
who want complete control over every step.

pip install aip-protocol
python examples/04_full_pipeline.py
"""

from aip_protocol import (
    AgentPassport,
    create_envelope,
    sign_envelope,
    verify_intent,
    RevocationStore,
    VerificationTier,
)


if __name__ == "__main__":
    # ── Step 1: Create an Agent Passport ─────────────────────────────
    passport = AgentPassport.create(
        domain="acme-corp.com",
        agent_name="procurement-bot",
        principal_id="did:web:acme-corp.com",
        allowed_actions=["read_invoice", "approve_payment", "send_notification"],
        denied_actions=["delete_data", "wire_transfer_international"],
        monetary_limit_per_txn=500.0,
        monetary_limit_per_day=5000.0,
    )
    print(f"Agent: {passport.agent_id}")

    # ── Step 2: Create an Intent Envelope ────────────────────────────
    envelope = create_envelope(
        passport=passport,
        action="approve_payment",
        target="did:web:vendor.com:agents:billing",
        parameters={"amount": 200.00, "currency": "USD", "invoice_id": "INV-2026-42"},
    )
    print(f"Intent: {envelope.intent.action} → {envelope.intent.target}")
    print(f"Tier: {envelope.verification_tier.value}")

    # ── Step 3: Sign the Envelope ────────────────────────────────────
    signed = sign_envelope(envelope, passport.private_key)
    print(f"Signature: {signed.proof.proof_value[:32]}...")

    # ── Step 4: Verify ───────────────────────────────────────────────
    store = RevocationStore()
    result = verify_intent(
        envelope=signed,
        public_key=passport.public_key,
        revocation_store=store,
    )

    print()
    print(f"Verified: {result.valid}")
    print(f"Signature OK: {result.signature_valid}")
    print(f"Within Boundaries: {result.within_boundaries}")
    print(f"Trust Score: {result.trust_score}")

    if result.errors:
        print(f"Errors: {[e.value for e in result.errors]}")
    else:
        print("✅ Agent is authorized to approve this payment")

    # ── Step 5: Try a violation ──────────────────────────────────────
    print()
    print("--- Attempting boundary violation ---")
    bad_envelope = create_envelope(
        passport=passport,
        action="approve_payment",
        target="did:web:vendor.com",
        parameters={"amount": 15000.00, "currency": "USD"},
    )
    bad_signed = sign_envelope(bad_envelope, passport.private_key)
    bad_result = verify_intent(
        envelope=bad_signed,
        public_key=passport.public_key,
        revocation_store=store,
    )
    print(f"Verified: {bad_result.valid}")
    print(f"Errors: {[e.value for e in bad_result.errors]}")
    print("❌ $15,000 payment blocked — exceeds $500 per-transaction limit")
