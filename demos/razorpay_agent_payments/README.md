# AIP × Razorpay — action-level authorization for agent payments

```bash
python -m demos.razorpay_agent_payments.razorpay_demo
```

Runs with no credentials at all. Add them for the live paths:

```bash
export RAZORPAY_KEY_ID=rzp_test_...  RAZORPAY_KEY_SECRET=...   # real test-mode API
export ANTHROPIC_API_KEY=sk-ant-...                            # real Claude tool-use loop
```

## What this is for

UPI Reserve Pay already solves the amount. NPCI's Single Block Multi Debit
reserves a reservoir against a merchant — up to ₹10,000, up to 90 days,
revocable, with a notification per debit. That is the right primitive, at the
right layer, and this demo does not try to replace it.

What it does not decide is **what the agent does inside that reserve**. Every
one of these is a legal debit against a valid block:

- a payment to a payee nobody approved
- a refund, when the agent was only ever meant to collect
- twenty small payments that add up past what anyone intended

That is the gap this sits in.

```
LLM agent  ──►  AIP Gateway  ──►  Razorpay MCP / API
                    │
                    └──►  audit row for every allow AND deny
```

## The split that makes it work

The agent signs its own intent envelope, so it cannot be trusted to declare
its own limits — it holds that key. The **merchant treasury** signs a
mandate with a key the agent never sees, and the verifier checks the intent
against the mandate rather than against anything the agent claims about
itself.

```python
mandate = issue_mandate(
    issuer="did:web:acme-retail.in",
    subject=agent.agent_id,
    boundaries=Boundaries(
        allowed_actions=["create_payment_link", "fetch_payments"],
        denied_actions=["create_refund"],
        monetary_limit=MonetaryLimit(per_transaction=1000.0, per_day=2000.0,
                                     currency="INR"),
    ),
    issuer_private_key=treasury_private,   # the agent does not have this
)
```

A compromised agent can forge an envelope. It cannot forge this.

## What the demo shows

| Scene | Result |
|---|---|
| Payment inside the mandate | Authorized, real Razorpay id |
| Prompt-injected ₹45,000 payout | `AIP-E202` before any network call |
| 20 × ₹99 against a ₹2,000 daily cap | 12 approved, 8 refused |
| Kill switch mid-session | `AIP-E400`, even on read-only calls |
| Audit + latency | Every decision, ~1.5ms p50 |

## Notes on how it fails

Both external dependencies degrade rather than crash — no Razorpay
credentials falls back to a labelled simulation, no LLM credentials replays a
recorded tool-call trace. The demo runs for anyone who clones the repo.

A refusal is returned to the model as a `tool_result` with `is_error: true`
carrying the AIP code, so the agent finds out in-band and can say what
happened, instead of the process raising or the payment silently vanishing.

Amounts are integer paise throughout. Money is never compared as a float —
`0.1 + 0.2 > 0.3` is true in binary floating point, and a limit check that is
wrong by one ulp is a limit check you can walk through.
