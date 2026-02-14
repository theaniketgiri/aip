# RFC-001: Agent Intent Protocol (AIP-1)

**Title:** The Death of the Chatbot and the Birth of the Agentic Web  
**Status:** Public Draft  
**Date:** February 2026  
**Authors:** KYA Labs (team@synthexai.tech)  
**Discussion:** [GitHub Issues](https://github.com/theaniketgiri/aip/issues)

---

## Abstract

We propose AIP-1 (Agent Intent Protocol), a neutral, open standard for verifying the identity, intent, and authorization boundaries of autonomous AI agents before execution. AIP provides cryptographic proof-of-intent — enabling trustless agent-to-agent commerce without human oversight.

## 1. Motivation

We are witnessing the most significant platform shift since the mobile internet: the transition from "Chat with AI" to the **Agent-to-Agent Economy**.

But there is a fatal flaw in the foundation.

### 1.1 The Black Box Agent Problem

Today, if you let an AI agent book flights, move money, or manage your calendar, you are trusting a black box.

- You don't know **who** the agent is (Identity)
- You don't know **what** it will do until it does it (Intent)
- You don't know **where** it stops (Boundary)

We are building a world of autonomous software without a driver's license system.

This is why enterprises are terrified to deploy agents in production. The risk of a "rogue agent" hallucinating a $50,000 transaction is too high. The cost of **not having verification** will be measured in lawsuits, not bugs.

### 1.2 Why Existing Solutions Fail

| Approach | Limitation |
|---|---|
| API Keys | Authenticate the *caller*, not the *intent*. An agent with valid API keys can still act outside its mandate. |
| RBAC / IAM | Static permissions. Agents need dynamic, per-action, context-aware boundaries. |
| Human-in-the-loop | Defeats the purpose of autonomy. Doesn't scale to 1000+ agent interactions/sec. |
| Prompt engineering | "Please don't do bad things" is not a security boundary. |
| Guardrails / output filters | Post-hoc. The damage is done by the time the filter catches it. |

AIP is **pre-execution verification**. The intent is cryptographically proven *before* any action is taken.

## 2. Protocol Overview

AIP-1 introduces four primitives:

### 2.1 Agent Passport

Every agent is a verifiable entity with a cryptographic identity:

```
did:web:acme-corp.com:agents:procurement-v1
```

A passport contains:
- **Ed25519 keypair** — cryptographic identity
- **DID-based address** — globally unique, resolvable
- **Boundary cage** — allowed actions, monetary limits, geo restrictions
- **Attestation** — framework, model hash, prompt hash (optional)

### 2.2 Intent Envelope

Before an agent acts, it constructs and signs an Intent Envelope:

```json
{
  "protocol_version": "AIP-1",
  "agent": {
    "id": "did:web:acme-corp.com:agents:procurement-v1",
    "domain": "acme-corp.com"
  },
  "intent": {
    "action": "transfer_funds",
    "target": "did:web:vendor.com:agents:billing",
    "parameters": { "amount": 45.00, "currency": "USD" }
  },
  "boundaries": {
    "allowed_actions": ["transfer_funds", "read_invoice"],
    "monetary_limit_per_txn": 50.00
  },
  "proof": {
    "type": "Ed25519Signature2024",
    "proof_value": "base64-encoded-signature"
  },
  "expires_at": "2026-02-14T12:00:00Z",
  "entropy": "unique-nonce-for-replay-prevention"
}
```

### 2.3 Verification Pipeline

The receiving agent (or a verification gateway) validates the envelope through an 8-step pipeline:

```
① Version Check       → Is this AIP-1?
② Schema Validation   → Is the envelope well-formed?
③ Expiry Check        → Has this intent expired?
④ Replay Detection    → Has this nonce been used before?
⑤ Signature Check     → Does the Ed25519 signature match?
⑥ Boundary Check      → Is this action within the agent's cage?
⑦ Revocation Check    → Has this agent been revoked or suspended?
⑧ Trust Evaluation    → Does this agent have sufficient trust score?
```

### 2.4 Trust Score

Trust is not granted — it is **earned**.

Every successful verification increases an agent's trust score (Bayesian model). Every boundary violation, failed attestation, or anomalous pattern decreases it. Trust scores are local to each verifier — there is no central trust authority.

## 3. Tiered Verification

Not every intent requires full cryptographic verification. AIP auto-selects the verification tier based on risk:

| Tier | Use Case | Latency | Steps |
|---|---|---|---|
| **Tier 0** | Low-risk, cached, in-session repeats | <1ms | HMAC + boundary proof |
| **Tier 1** | Normal operations | ~5ms | Ed25519 + boundary + revocation |
| **Tier 2** | High-value, cross-org, first contact | ~50-100ms | Full 8-step pipeline + intent drift + delegation |

Tier selection is automatic based on:
- Transaction value relative to limits
- Agent familiarity (first contact vs. established)
- Cross-organization boundary crossing
- Action risk classification

## 4. Kill Switch

Any agent can be **revoked** (permanently) or **suspended** (temporarily) with zero propagation delay. A revoked agent's intents are rejected at every tier — including Tier 0.

This is the circuit breaker for the agentic web. If an agent goes rogue at 3am, you don't need to wake up an engineer. You hit the kill switch.

## 5. Error Taxonomy

AIP defines 22 machine-readable error codes across 5 categories:

| Range | Category | Purpose |
|---|---|---|
| `AIP-E1xx` | Envelope Errors | Signature, expiry, replay, schema failures |
| `AIP-E2xx` | Boundary Violations | Action not allowed, monetary limit, geo restriction |
| `AIP-E3xx` | Attestation Failures | Model hash mismatch, framework mismatch, intent drift |
| `AIP-E4xx` | Trust & Revocation | Agent revoked, suspended, delegation invalid, trust too low |
| `AIP-E5xx` | Protocol Errors | Mesh unavailable, handshake timeout |

Every rejection is auditable. Every audit trail is machine-readable.

## 6. The Verification Mesh (Vision)

AIP is not a platform. It is a **handshake**.

The long-term vision is a Verification Mesh — a decentralized network where:

1. A procurement agent from Acme Corp buys servers from an agent at AWS
2. The AWS agent automatically trusts the Acme agent based on its Trust Score
3. If the Acme agent tries to buy $1M worth of servers (above its boundary), the transaction is **mathematically rejected** before it hits the database
4. No humans involved. Just cryptographically secure, high-speed agency

The mesh is protocol-level infrastructure — like TCP/IP for agent trust.

## 7. Framework Compatibility

AIP is framework-agnostic:

| Framework | Integration |
|---|---|
| LangChain / LangGraph | ✅ Framework attestation via `framework_id` |
| CrewAI | ✅ Per-agent passport, shared trust mesh |
| AutoGPT | ✅ Boundary enforcement on plugin calls |
| Microsoft AutoGen | ✅ Multi-agent conversation verification |
| Custom agents | ✅ Any Python runtime — `pip install aip-protocol` |

## 8. Reference Implementation

The reference implementation is open-source (MIT):

- **SDK:** [PyPI — aip-protocol](https://pypi.org/project/aip-protocol/)
- **Source:** [github.com/theaniketgiri/aip](https://github.com/theaniketgiri/aip)
- **Live Dashboard:** [aip.synthexai.tech](https://aip.synthexai.tech)
- **Test Suite:** 63 tests covering all verification tiers, boundary types, and edge cases

```bash
pip install aip-protocol
```

## 9. Call for Design Partners

We are seeking **3 design partners** for the first production deployments of AIP-1:

| Vertical | Use Case |
|---|---|
| **Fintech** | Secure autonomous trading agents with monetary boundaries |
| **Enterprise** | Employee-onboarding agents with strict permission cages |
| **Gov/Defense** | High-assurance audit trails for autonomous systems |

Partners receive:
- Enterprise API access (free during beta)
- Direct engineering support
- Protocol roadmap influence

→ **Contact:** team@synthexai.tech  
→ **Apply:** [aip.synthexai.tech](https://aip.synthexai.tech)

## 10. Open Questions

We invite the community to discuss:

1. **Cross-mesh trust federation** — How should trust scores propagate across organizational boundaries?
2. **Delegation depth limits** — What is the maximum safe delegation chain length?
3. **Quantum readiness** — When should AIP migrate from Ed25519 to post-quantum signatures?
4. **Regulatory mapping** — How does AIP align with EU AI Act agent accountability requirements?

## License

This specification is released under the MIT License.

The protocol is open. The implementation is open. The future of the agentic web should be built on open standards.

---

<p align="center">
  <strong>KYA Labs</strong> — Know Your Agent before it acts.<br/>
  <a href="https://aip.synthexai.tech">aip.synthexai.tech</a>
</p>
