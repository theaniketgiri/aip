# AIP × LangChain — Protected Tools Demo

A LangChain agent with 4 tools, each AIP-protected with different boundaries. Every tool call is cryptographically verified before execution.

## Tools & Permissions

| Tool | Status | Limit | Notes |
|------|--------|-------|-------|
| **search_database** | ✅ Allowed | — | Read-only, no monetary limit |
| **send_email** | ✅ Allowed | — | Notification, no monetary limit |
| **transfer_funds** | ✅ Allowed | $500/txn | Monetary cap enforced |
| **delete_records** | ❌ Denied | — | Explicitly forbidden |

## Scenarios

1. ✅ Database search — passes verification
2. ✅ Send email — passes verification
3. ✅ Transfer $200 — within $500 limit, passes
4. ❌ Transfer $5,000 — exceeds $500 limit, **BLOCKED**
5. ❌ Delete records — denied action, **BLOCKED**
6. 🔴 Kill switch — agent revoked, all tools dead
7. 🔄 Reinstatement — agent restored, tools work again

## Run

```bash
pip install aip-protocol
python langchain_demo.py
```

No LLM API key required.
