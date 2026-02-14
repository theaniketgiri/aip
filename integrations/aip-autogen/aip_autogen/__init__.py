"""
aip-autogen — Microsoft AutoGen integration for the Agent Intent Protocol.

Usage:
    from aip_autogen import aip_wrap

    assistant = aip_wrap(assistant, actions=["respond"], limit=500)

Every message exchange is AIP-verified.
"""

from aip_autogen.core import aip_wrap, AIPConversation

__all__ = ["aip_wrap", "AIPConversation"]
__version__ = "0.1.0"
