"""
aip-crewai — CrewAI integration for the Agent Intent Protocol.

Usage:
    from aip_crewai import aip_agent

    protected = aip_agent(my_agent, actions=["research"], limit=100)

Every task execution is AIP-verified before running.
"""

from aip_crewai.core import aip_agent, aip_task, AIPCrew

__all__ = ["aip_agent", "aip_task", "AIPCrew"]
__version__ = "0.1.0"
