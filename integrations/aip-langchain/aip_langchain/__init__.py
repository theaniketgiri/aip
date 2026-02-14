"""
aip-langchain — LangChain integration for the Agent Intent Protocol.

Usage:
    from aip_langchain import aip_tool

    @aip_tool(limit=500)
    def transfer_funds(amount: float, to: str) -> str:
        '''Transfer funds to a recipient.'''
        return f"Sent ${amount} to {to}"

Every tool call is cryptographically signed, boundary-checked,
and verified through the AIP pipeline — automatically.
"""

from aip_langchain.tools import aip_tool, AIPTool, AIPToolkit

__all__ = ["aip_tool", "AIPTool", "AIPToolkit"]
__version__ = "0.1.0"
