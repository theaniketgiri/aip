# aip-langchain

LangChain integration for the **Agent Intent Protocol (AIP)**.

Every tool call your LangChain agent makes gets cryptographically signed, boundary-checked, and verified — automatically.

## Install

```bash
pip install aip-protocol langchain langchain-openai
```

## Usage — 2 lines

```python
from aip_langchain import aip_tool

@aip_tool(limit=500)
def transfer_funds(amount: float, to: str) -> str:
    """Transfer funds to a recipient."""
    return f"Sent ${amount} to {to}"

# Use in any LangChain agent — AIP verification is automatic
```

## Full Agent Example

```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate
from aip_langchain import aip_tool, AIPToolkit

# Define tools with AIP protection
@aip_tool(limit=500, geo="US")
def transfer_funds(amount: float, to: str) -> str:
    """Transfer funds to a recipient."""
    return f"Sent ${amount} to {to}"

@aip_tool(actions=["read_data"])
def read_invoice(invoice_id: str) -> str:
    """Read an invoice by ID."""
    return f"Invoice {invoice_id}: $250.00"

# Create agent
llm = ChatOpenAI(model="gpt-4o")
tools = [transfer_funds, read_invoice]

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a procurement agent."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)

result = executor.invoke({"input": "Transfer $200 to Acme Corp"})
# ✅ AIP verifies: action=transfer_funds, amount=200 < limit=500
```

## API

### `@aip_tool` Decorator

```python
@aip_tool(
    limit=500,          # Per-transaction monetary limit
    daily_limit=5000,   # Per-day limit
    actions=["pay"],    # Allowed actions (default: [function_name])
    denied=["delete"],  # Denied actions
    geo="US",           # Geographic restriction
    domain="acme.com",  # DID domain
    on_violation="raise",  # "raise" | "return_error" | "log"
)
def my_tool(...): ...
```

### `AIPToolkit`

```python
from aip_langchain import AIPToolkit

# Wrap existing tools
toolkit = AIPToolkit(limit=500, domain="acme.com")
protected_tools = toolkit.wrap_tools([tool1, tool2, tool3])
```

## License

MIT — [AIP Protocol](https://github.com/theaniketgiri/aip)
