# AIP Protocol — Agent Intent Protocol

> **Proof of Intent for the Agentic Web** · [Live Dashboard](https://aip.synthexai.tech) · [API Docs](https://aip.synthexai.tech/api/health)

AIP-1 is a trustless, cross-platform protocol for verifying the identity, intent, and authorization boundaries of autonomous AI agents. Think of it as **OAuth + TLS, but for AI agents talking to each other**.

Built by [KYA Labs](https://aip.synthexai.tech) — *Know Your Agent before it acts.*

---

## Why AIP?

Every AI framework lets agents **do things**. None of them verify **what agents are allowed to do**. AIP fixes this:

- 🔐 **Cryptographic Identity** — Ed25519 keypair per agent, DID-based addressing
- 🧱 **Boundary Enforcement** — Action allowlists, monetary limits, domain scoping
- ✅ **Tiered Verification** — Sub-millisecond for low-risk, full crypto for high-value
- 🔴 **Kill Switch** — Revoke or suspend any agent in real-time
- 📊 **Trust Scores** — Bayesian reputation based on historical behavior

## Install

```bash
pip install aip-protocol
```

Or from source:

```bash
git clone https://github.com/theaniketgiri/aip.git
cd aip
pip install -e ".[dev]"
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

## Hosted API

Don't want to self-host verification? Use our cloud API:

```bash
# Get an API key
curl -X POST https://aip.synthexai.tech/api/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "my-app", "plan": "starter"}'

# Verify an agent intent
curl -X POST https://aip.synthexai.tech/api/verify \
  -H "X-API-Key: kya_YOUR_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "did:web:example.com:agents:my-bot", "action": "transfer_funds"}'
```

**Pricing:** $0.005/verification (Starter) · $0.003 (Pro) · $0.001 (Enterprise)

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
# 63 tests, all passing
```

## Design Partners

We're looking for **3 early partners** building multi-agent systems. You get:
- Free Enterprise API access during beta
- Direct Slack channel with the team
- Your feedback shapes the protocol

**Interested?** Open an issue or reach out → [Dashboard](https://aip.synthexai.tech)

## License

MIT
