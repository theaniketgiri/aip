"""
AIP Protocol — Agent Intent Protocol SDK
Proof of Intent for the Agentic Web
"""

__version__ = "0.4.0"

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
from aip_protocol.ledger import SpendLedger
from aip_protocol.mandate import Mandate, issue_mandate, verify_mandate
from aip_protocol.money import to_minor, from_minor, format_minor, MoneyError
from aip_protocol.crypto import generate_keypair, hmac_sign, hmac_verify, generate_hmac_key
from aip_protocol.shield import protect, protect_agent, shield, shield_class, shield_object, AIPViolation
from aip_protocol.observe import (
    observe,
    observe_agent,
    passport,
    ObservationEvent,
    ObservationStore,
    get_observation_store,
    set_observation_store,
)

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
    "SpendLedger",
    "Mandate",
    "issue_mandate",
    "verify_mandate",
    "to_minor",
    "from_minor",
    "format_minor",
    "MoneyError",
    "generate_keypair",
    "generate_hmac_key",
    "hmac_sign",
    "hmac_verify",
    # One-liner API (helmet-level easy)
    "protect",
    "protect_agent",
    "shield",
    "shield_class",
    "shield_object",
    "AIPViolation",
    # Observability (free tier)
    "observe",
    "observe_agent",
    "passport",
    "ObservationEvent",
    "ObservationStore",
    "get_observation_store",
    "set_observation_store",
]
