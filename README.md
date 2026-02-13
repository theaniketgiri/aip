# AIP Protocol — Agent Intent Protocol SDK

> **Proof of Intent for the Agentic Web**

AIP-1 is a trustless, cross-platform protocol for verifying the identity, intent, and authorization boundaries of autonomous AI agents. Think of it as **OAuth + TLS, but for AI agents talking to each other**.

## Install

```bash
pip install -e .
```

## Quick Start

```python
from aip_protocol import AgentPassport, create_envelope, sign_envelope, verify_intent
from aip_protocol.revocation import RevocationStore

# 1. Create an agent passport
passport = AgentPassport.create(
    domain="entripse.com",
    agent_name="procurement-v1",
    allowed_actions=["read_invoice", "transfer_funds"],
    monetary_limit_per_txn=50.0,
)
passport.save("./my_agent")

# 2. Create and sign an intent
envelope = create_envelope(
    passport,
    action="transfer_funds",
    target="did:web:vendor.com",
    parameters={"amount": 45.00, "currency": "USD"},
)
signed = sign_envelope(envelope, passport.private_key)

# 3. Verify the intent (verifier side)
store = RevocationStore()
result = verify_intent(signed, passport.public_key, revocation_store=store)

if result.passed:
    print("✓ Intent verified — execute action")
else:
    print(f"✗ Rejected: {result.errors}")
```

## CLI

```bash
# Create a passport
aip create-passport --domain entripse.com --name procurement-v1 -a transfer_funds -m 50

# Sign an intent
aip sign-intent --passport ./agent_passport --action transfer_funds --amount 45 -o intent.json

# Verify
aip verify --envelope intent.json --public-key ./agent_passport/public.pem

# Revoke an agent
aip revoke "did:web:entripse.com:agents:procurement-v1" --reason "compromised"
```

## Architecture

```
┌─────────────────────────────────────────────┐
│              Intent Envelope                │
│  ┌─────────┐ ┌──────────┐ ┌──────────────┐ │
│  │  Agent   │ │  Intent  │ │  Boundaries  │ │
│  │ Identity │ │  Action  │ │ (The Cage)   │ │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘ │
│       └────────────┼──────────────┘         │
│              ┌─────▼─────┐                  │
│              │   Proof    │ ← Ed25519 sig   │
│              └───────────┘                  │
└─────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│          Verification Mesh                  │
│  1. Version Check    5. Attestation Verify  │
│  2. Schema Check     6. Revocation Check    │
│  3. Expiry Check     7. Trust Score Check   │
│  4. Boundary Check   8. Accept / Reject     │
└─────────────────────────────────────────────┘
```

## Tiered Verification

Not every intent needs full crypto. AIP auto-selects the verification tier:

| Tier | When | Latency |
|---|---|---|
| **Tier 0** | Low-risk, in-session repeats | <1ms |
| **Tier 1** | Normal operations | ~5ms |
| **Tier 2** | High-value, cross-org, first contact | ~100ms |

## Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
