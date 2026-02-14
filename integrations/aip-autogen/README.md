# aip-autogen

Microsoft AutoGen integration for the **Agent Intent Protocol (AIP)**.

Every message between AutoGen agents is cryptographically signed, boundary-checked, and verified.

## Install

```bash
pip install aip-protocol pyautogen
```

## Usage

```python
from autogen import AssistantAgent, UserProxyAgent
from aip_autogen import aip_wrap, AIPConversation

# Create agents
assistant = AssistantAgent("assistant", llm_config={...})
user_proxy = UserProxyAgent("user_proxy")

# Wrap with AIP — 1 line per agent
assistant = aip_wrap(assistant, actions=["respond", "analyze"], limit=500)
user_proxy = aip_wrap(user_proxy, actions=["request", "approve"])

# Or wrap an entire conversation
conv = AIPConversation(
    agents=[assistant, user_proxy],
    limit=500,
    domain="acme.com",
)

# Every message exchange is now AIP-verified
user_proxy.initiate_chat(assistant, message="Analyze Q4 earnings")
```

## License

MIT — [AIP Protocol](https://github.com/theaniketgiri/aip)
