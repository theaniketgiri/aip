"""
AIP + LangChain — Protect LangChain tools with AIP.

Every tool call your LangChain agent makes is cryptographically
verified before execution.

pip install aip-protocol langchain-core
python examples/06_langchain.py
"""

# NOTE: This example uses aip-langchain from the integrations/ folder.
# In production: pip install aip-langchain

import sys
sys.path.insert(0, "../integrations/aip-langchain")

from aip_langchain import aip_tool, AIPToolkit


# ── Protect tools with @aip_tool ─────────────────────────────────────────

@aip_tool(limit=500, actions=["transfer_funds"])
def transfer_funds(amount: float, to: str) -> str:
    """Transfer funds to a recipient."""
    return f"✅ Sent ${amount:.2f} to {to}"


@aip_tool(actions=["read_invoice"])
def read_invoice(invoice_id: str) -> str:
    """Read an invoice by ID."""
    return f"✅ Invoice {invoice_id}: $250.00 from Acme Corp"


if __name__ == "__main__":
    print("=== AIP + LangChain ===")
    print()

    # These are real LangChain BaseTool instances
    print(f"Tool: {transfer_funds.name}")
    print(f"Description: {transfer_funds.description}")
    print()

    # ✅ Valid tool call
    result = transfer_funds.run({"amount": 200, "to": "Acme Corp"})
    print(f"Result: {result}")

    # ✅ Read invoice
    result2 = read_invoice.run({"invoice_id": "INV-2026-42"})
    print(f"Result: {result2}")

    # ❌ Over limit
    print()
    try:
        transfer_funds.run({"amount": 5000, "to": "Evil Corp"})
    except Exception as e:
        print(f"❌ BLOCKED: {e}")

    print()
    print("These tools work with any LangChain agent:")
    print("  agent = create_tool_calling_agent(llm, [transfer_funds, read_invoice], prompt)")
    print("  executor = AgentExecutor(agent=agent, tools=[transfer_funds, read_invoice])")
    print("  executor.invoke({'input': 'Pay Acme $200'})")
