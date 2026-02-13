"""
AIP Protocol — Agent Intent Protocol SDK
Proof of Intent for the Agentic Web
"""

__version__ = "0.1.0"

from aip_protocol.models import (
    AgentIdentity,
    Attestation,
    Boundaries,
    DelegationLink,
    IntentEnvelope,
    MonetaryLimit,
    Principal,
    TimeWindow,
    VerificationResult,
    VerificationTier,
)
from aip_protocol.passport import AgentPassport
from aip_protocol.envelope import create_envelope, sign_envelope
from aip_protocol.verification import verify_intent
from aip_protocol.errors import AIPError, AIPErrorCode
from aip_protocol.revocation import RevocationStore

__all__ = [
    "AgentPassport",
    "AgentIdentity",
    "Attestation",
    "Boundaries",
    "DelegationLink",
    "IntentEnvelope",
    "MonetaryLimit",
    "Principal",
    "TimeWindow",
    "VerificationResult",
    "VerificationTier",
    "create_envelope",
    "sign_envelope",
    "verify_intent",
    "AIPError",
    "AIPErrorCode",
    "RevocationStore",
]
