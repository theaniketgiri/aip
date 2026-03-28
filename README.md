<p align="center">
  <img src="https://img.shields.io/badge/Protocol-AIP--1-0B0D10?style=for-the-badge&labelColor=0B0D10&color=ABDBE3" alt="AIP-1" />
  <img src="https://img.shields.io/badge/Crypto-Ed25519-0B0D10?style=for-the-badge&labelColor=0B0D10&color=34D399" alt="Ed25519" />
  <img src="https://img.shields.io/pypi/v/aip-protocol?style=for-the-badge&labelColor=0B0D10&color=A78BFA&label=PyPI" alt="PyPI" />
  <img src="https://img.shields.io/badge/Tests-63%20passing-0B0D10?style=for-the-badge&labelColor=0B0D10&color=34D399" alt="Tests" />
  <img src="https://img.shields.io/badge/License-MIT-0B0D10?style=for-the-badge&labelColor=0B0D10&color=94A3B8" alt="License" />
</p>

<h1 align="center">AIP — Agent Intent Protocol</h1>

<p align="center">
  <strong>The HTTPS for AI Agents.</strong><br/>
  Cryptographic identity, intent verification, and boundary enforcement for autonomous agents.
</p>

<p align="center">
  <a href="https://aip.synthexai.tech/docs">Documentation</a> ·
  <a href="https://aip.synthexai.tech">Live Dashboard</a> ·
  <a href="https://pypi.org/project/aip-protocol/">PyPI</a>
</p>

---

## The Problem

Every AI framework lets agents **do things**. None of them verify **what agents are allowed to do**.

A LangChain agent can drain a bank account. An AutoGPT agent can email your customers. A CrewAI agent can delete production data. There is no standard way to verify an agent's identity, enforce its boundaries, or revoke it in real-time.

**AIP fixes this.**

## What is AIP?

AIP-1 is a trustless, cross-platform protocol for verifying the **identity**, **intent**, and **authorization boundaries** of autonomous AI agents before they act.

Think of it as **OAuth + TLS, purpose-built for the agentic web**.

```
Agent wants to act → Creates signed Intent Envelope → Verifier checks 8-step pipeline → Allow or Deny
```

### Core Capabilities

| Capability | What it does |
|---|---|
| **Cryptographic Identity** | Ed25519 keypair per agent, DID-based addressing (`did:web:`) |
| **Boundary Enforcement** | Action allowlists, deny lists, monetary limits, geo restrictions |
| **Tiered Verification** | Sub-millisecond for low-risk, full crypto for high-value intents |
| **Kill Switch** | Revoke or suspend any agent globally with zero propagation delay |
| **Trust Scores** | Bayesian reputation model — trust is earned over successful verifications |
| **Intent Drift Detection** | Semantic classifier flags actions outside an agent's declared scope |
| **Structured Error Codes** | 22 machine-readable `AIP-Exxx` codes across 5 categories for audit trails |

## Install

```bash
pip install aip-protocol
```

## Quick Start

```python
from aip_protocol import AgentPassport, create_envelope, sign_envelope, verify_intent
from aip_protocol.revocation import RevocationStore

# 1 — Create an agent passport (identity + keys + boundaries)
passport = AgentPassport.create(
    domain="yourco.com",
    agent_name="procurement-bot",
    allowed_actions=["read_invoice", "transfer_funds"],
    monetary_limit_per_txn=50.0,
)

print(passport.agent_id)
# → "did:web:yourco.com:agents:procurement-bot"

# 2 — Agent wants to act: create and sign an intent envelope
envelope = create_envelope(
    passport,
    action="transfer_funds",
    target="did:web:vendor.com",
    parameters={"amount": 45.00, "currency": "USD"},
)
signed = sign_envelope(envelope, passport.private_key)

# 3 — Verifier checks the intent through the 8-step pipeline
store = RevocationStore()
result = verify_intent(signed, passport.public_key, revocation_store=store)

if result.passed:
    print(f"✓ Verified — tier: {result.tier_used.value}, trust: {result.trust_score}")
else:
    for error in result.errors:
        print(f"✗ {error.value}: {error.name}")
    # e.g. "✗ AIP-E202: MONETARY_LIMIT"
```

## Verification Pipeline

Every intent passes through an 8-step verification pipeline. The protocol auto-selects the verification tier based on risk:

```
┌────────────────────────────────────────────────────────┐
│                   Intent Envelope                      │
│  ┌───────────┐  ┌───────────┐  ┌────────────────────┐ │
│  │  Agent ID  │  │  Intent   │  │  Boundaries        │ │
│  │  (DID)     │  │  (Action) │  │  (The Cage)        │ │
│  └─────┬──────┘  └─────┬─────┘  └──────────┬─────────┘ │
│        └───────────────┼────────────────────┘           │
│                  ┌─────▼─────┐                          │
│                  │   Proof   │ ← Ed25519 signature      │
│                  └───────────┘                          │
└────────────────────────────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│               Verification Pipeline                    │
│                                                        │
│  ① Version Check       ⑤ Attestation Verify           │
│  ② Schema Validation   ⑥ Revocation Check             │
│  ③ Expiry Check        ⑦ Trust Score Evaluation        │
│  ④ Boundary Check      ⑧ Final Verdict                │
│     └─ Actions                                         │
│     └─ Monetary limits                                 │
│     └─ Geo restrictions                                │
│     └─ Intent drift                                    │
└────────────────────────────────────────────────────────┘
```

### Tiered Verification

Not every intent needs full cryptographic verification. AIP auto-selects the tier:

| Tier | Use Case | Latency | What Runs |
|---|---|---|---|
| **Tier 0** | Low-risk, cached, in-session repeats | **<1ms** | HMAC + boundary proof |
| **Tier 1** | Normal operations | **~5ms** | Ed25519 + boundary + revocation |
| **Tier 2** | High-value, cross-org, first contact | **~50–100ms** | Full 8-step pipeline |

## Error Taxonomy

Every failure returns a machine-readable `AIP-Exxx` code — not a generic 400. Your logs, dashboards, and audit trails show *exactly* what went wrong.

| Range | Category | Examples |
|---|---|---|
| `AIP-E1xx` | **Envelope Errors** | `E100` Invalid Signature · `E101` Expired · `E102` Replay Detected |
| `AIP-E2xx` | **Boundary Violations** | `E200` Action Not Allowed · `E202` Monetary Limit · `E204` Geo Restricted |
| `AIP-E3xx` | **Attestation Failures** | `E300` Model Hash Mismatch · `E303` Intent Drift |
| `AIP-E4xx` | **Trust Failures** | `E400` Agent Revoked · `E403` Delegation Invalid · `E404` Trust Too Low |
| `AIP-E5xx` | **Protocol Errors** | `E500` Mesh Unavailable · `E502` Handshake Timeout |

Full reference → [aip.synthexai.tech/docs#errors](https://aip.synthexai.tech/docs#errors)

## CLI

```bash
# Create a passport
aip create-passport --domain yourco.com --name my-agent \
  -a read_data -a transfer_funds -m 100

# Sign an intent
aip sign-intent --passport ./agent_passport \
  --action transfer_funds --amount 45 -o intent.json

# Verify an intent
aip verify --envelope intent.json \
  --public-key ./agent_passport/public.pem

# Revoke an agent instantly
aip revoke "did:web:yourco.com:agents:my-agent" --reason "compromised"
```

## Shield — One-Liner Protection

Shield is the **helmet.js for AI agents**. Wrap any function, class, or object with AIP verification in a single line:

```python
from aip_protocol import shield, shield_class, shield_object

# Wrap a function — every call is verified before execution
@shield(passport, allowed_actions=["transfer_funds"], monetary_limit=100.0)
def send_payment(to: str, amount: float):
    bank.transfer(to, amount)

send_payment("vendor@acme.com", 45.00)  # ✓ Verified and executed
send_payment("vendor@acme.com", 500.00) # ✗ AIP-E202: MONETARY_LIMIT

# Wrap an entire class — all public methods get AIP protection
@shield_class(passport)
class TradingAgent:
    def buy_stock(self, ticker, qty): ...
    def sell_stock(self, ticker, qty): ...

# Or patch an existing object at runtime
agent = CrewAIAgent(...)
shield_object(agent, passport)  # All methods now AIP-verified
```

## Framework Integrations

AIP works with any AI agent framework. Here are production-ready examples:

### LangChain — Protected Tools

Wrap any LangChain tool with cryptographic verification. Every tool call is signed, verified, and auditable before execution.

**Problem it solves:** A LangChain agent with access to `transfer_funds` can be tricked by prompt injection into draining an account. AIP blocks unauthorized actions at the cryptographic layer — the tool never executes.

```python
from aip_protocol import AgentPassport, create_envelope, sign_envelope, verify_intent

passport = AgentPassport.create(
    domain="fintech.com",
    agent_name="assistant",
    allowed_actions=["search", "send_email", "transfer_funds"],
    denied_actions=["delete_records"],
    monetary_limit_per_txn=500,
)

# Agent tries to transfer $5,000 → BLOCKED (exceeds $500 limit)
# Agent tries to delete records → BLOCKED (denied action)
# Agent is compromised → KILL SWITCH → all tools dead instantly
```

→ **[Full LangChain Demo](demos/langchain_protected_tools/)**

### CrewAI — Multi-Agent Compliance

Give each agent in a crew its own cryptographic passport with different permissions. Revoke one agent without killing the crew.

```python
# Analyst: read-only, no monetary actions
analyst = AgentPassport.create(
    domain="acme-capital.com", agent_name="analyst-bot",
    allowed_actions=["research", "analyze"], denied_actions=["trade", "delete_records"],
    monetary_limit_per_txn=0,
)

# Trader: can trade up to $10K
trader = AgentPassport.create(
    domain="acme-capital.com", agent_name="trading-bot",
    allowed_actions=["trade", "analyze"], denied_actions=["delete_records"],
    monetary_limit_per_txn=10000,
)

# Kill only the rogue trader — analyst keeps working
store.revoke(agent_id=trader.agent_id, reason="anomalous_trading_pattern")
```

→ **[Full CrewAI Demo](demos/crewai_financial_compliance/)**

### Google ADK / Any Framework

AIP is framework-agnostic. The `shield` decorator works on any Python function:

```python
@shield(passport, allowed_actions=["query_db"], monetary_limit=1000.0)
def query_database(sql: str):
    return db.execute(sql)

# Works with Google ADK, AutoGen, DSPy, or plain Python
```

### Alternatives Compared

| Approach | Identity | Intent Verification | Kill Switch | Latency |
|----------|----------|-------------------|-------------|---------|
| API key scoping | ❌ No agent-level | ❌ No | ❌ No | – |
| Prompt guardrails | ❌ Bypassable | ❌ Probabilistic | ❌ No | – |
| LLM-as-judge | ❌ No | ⚠️ Probabilistic | ❌ No | ~500ms |
| **AIP** | ✅ Ed25519 | ✅ Deterministic | ✅ Instant | **<1ms** |

## AIP Cloud

The open-source SDK handles local verification. For production multi-agent systems, [AIP Cloud](https://aip.synthexai.tech) adds:

| Capability | Why It Can't Be Local |
|---|---|
| **Revocation Mesh** | Can't kill an agent across 50 deployments without a central service |
| **Persistent Trust Scores** | Trust history dies on restart, needs shared store |
| **Cross-Org Replay Detection** | Nonce cache is per-process — two companies can't share locally |
| **Compliance Audit Log** | SOC2/HIPAA needs immutable logs, local SQLite doesn't count |
| **Agent Identity Registry** | DNS for agents — `did:web:acme.com:agents:bot` needs a registry |
| **Framework Adapters** | Production CrewAI, LangChain, AutoGen with managed infrastructure |
| **Dashboard** | Real-time monitoring, kill switch, debugger |

→ **[Free tier available — aip.synthexai.tech](https://aip.synthexai.tech)**

## Development

```bash
git clone https://github.com/theaniketgiri/aip.git
cd aip
pip install -e ".[dev]"
pytest tests/ -v
# 63 tests, all passing
```

### Project Structure

```
aip_protocol/
├── passport.py       # Agent identity + Ed25519 key management
├── envelope.py       # Intent envelope creation + signing
├── verification.py   # 8-step verification pipeline + intent classifier
├── shield.py         # One-liner AIP protection (helmet.js for AI)
├── crypto.py         # Ed25519 + HMAC cryptographic layer
├── errors.py         # AIP-Exxx error taxonomy (22 structured codes)
├── revocation.py     # Real-time revocation store with rehydration
├── trust.py          # Bayesian trust score engine
├── models.py         # Protocol data models (Pydantic)
└── cli.py            # Command-line interface
```

## Design Partners

We're onboarding **early design partners** building multi-agent systems in production. Partners get:

- Enterprise-tier API access (free during beta)
- Direct engineering support from the core team
- Protocol roadmap influence
- Priority access to framework adapters

→ **[Apply at aip.synthexai.tech](https://aip.synthexai.tech)**

## License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub><strong>Korven</strong> — Know Your Agent before it acts.</sub><br/>
  <sub><a href="https://aip.synthexai.tech">Website</a> · <a href="https://aip.synthexai.tech/docs">API Docs</a> · <a href="https://pypi.org/project/aip-protocol/">PyPI</a></sub>
</p>
