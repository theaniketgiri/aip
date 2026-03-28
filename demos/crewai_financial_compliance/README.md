# AIP × CrewAI — Financial Compliance Demo

Three AI agents operating in a financial system, each with cryptographic passports and strict boundaries enforced by AIP.

## Agents

| Agent | Allowed Actions | Limit | Denied |
|-------|----------------|-------|--------|
| **AnalystAgent** | research, analyze, read_data | — | delete_records, trade, transfer_funds |
| **TradingAgent** | trade, analyze, read_data | $10,000/txn | delete_records |
| **AuditAgent** | read_data, generate_report | — | trade, delete_records, transfer_funds |

## Scenarios

1. ✅ Normal operations — all agents perform allowed actions
2. ❌ Monetary limit — TradingAgent tries $50K trade (limit: $10K)
3. ❌ Action boundary — AuditAgent tries to trade
4. ❌ Denied action — AnalystAgent tries to delete records
5. 🔴 Kill switch — TradingAgent revoked, all actions blocked
6. ✅ Selective revocation — other agents continue normally

## Run

```bash
pip install aip-protocol
python crewai_demo.py
```

No LLM API key required.
