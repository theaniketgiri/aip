"""
AIP Data Models — Pydantic schemas for the Agent Intent Protocol.

These models define the wire format for Intent Envelopes, Agent Passports,
boundaries, attestation, delegation chains, and verification results.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from aip_protocol.errors import AIPErrorCode


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VerificationTier(str, Enum):
    """Tiered verification — not every intent needs a ZKP."""
    TIER_0 = "tier_0"  # HMAC, cached boundary proof — <1ms
    TIER_1 = "tier_1"  # Ed25519 signature + boundary assertion — ~5ms
    TIER_2 = "tier_2"  # Full ZKP with privacy preservation — ~100-500ms


class AttestationMethod(str, Enum):
    """How the agent's model/runtime is attested."""
    SELF_REPORTED = "self_reported"        # V0 — agent claims its own hash
    FRAMEWORK_REGISTRY = "framework_registry"  # V1 — framework signs the build
    TEE_HARDWARE = "tee_hardware"          # V2 — hardware-attested (SGX/SEV)


class RevocationStatus(str, Enum):
    NOT_REVOKED = "not_revoked"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class IntentClassifier(BaseModel):
    """Lightweight intent classifier config — guardrail before signing."""
    model: str = "aip-classifier-v1"
    confidence_threshold: float = Field(default=0.95, ge=0.0, le=1.0)


class Attestation(BaseModel):
    """Agent attestation — proves the runtime hasn't been tampered with."""
    method: AttestationMethod = AttestationMethod.FRAMEWORK_REGISTRY
    framework_id: str | None = None  # e.g. "did:web:langchain.com"
    build_hash: str | None = None  # sha256 of the framework build
    system_prompt_hash: str | None = None  # sha256 of the system prompt template
    registry_signature: str | None = None  # framework's signature over build_hash
    intent_classifier: IntentClassifier = Field(default_factory=IntentClassifier)


class MonetaryLimit(BaseModel):
    """
    Monetary boundaries — the cage for financial actions.

    The wire format carries major units for readability, but ALL comparisons
    are performed on the `*_minor` integer properties. Never compare the float
    fields directly — see aip_protocol.money for why.
    """
    per_transaction: float = Field(default=0.0, ge=0.0)
    per_day: float = Field(default=0.0, ge=0.0)
    currency: str = "USD"

    @property
    def per_transaction_minor(self) -> int:
        """Per-transaction cap in exact integer minor units. 0 means no cap."""
        from aip_protocol.money import to_minor
        return to_minor(self.per_transaction, self.currency)

    @property
    def per_day_minor(self) -> int:
        """Rolling 24h cap in exact integer minor units. 0 means no cap."""
        from aip_protocol.money import to_minor
        return to_minor(self.per_day, self.currency)


class TimeWindow(BaseModel):
    """Time-based boundary — agent can only act within this window."""
    start: datetime
    end: datetime


class Boundaries(BaseModel):
    """The agent's cage — explicit can/cannot rules."""
    allowed_actions: list[str] = Field(default_factory=list)
    denied_actions: list[str] = Field(default_factory=list)
    monetary_limit: MonetaryLimit = Field(default_factory=MonetaryLimit)
    data_access: list[str] = Field(default_factory=list)
    geo_restriction: str | None = None
    time_window: TimeWindow | None = None


class DelegationLink(BaseModel):
    """One link in the delegation chain from principal → agent."""
    from_id: str = Field(alias="from")
    to_id: str = Field(alias="to")
    scope: str
    boundary_monotonicity: bool = True
    granted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None

    model_config = {"populate_by_name": True}


class Principal(BaseModel):
    """The human/org ultimately responsible for this agent."""
    type: str = "organization"  # "organization" | "individual"
    id: str  # e.g. "did:web:entripse.com"
    delegation_chain: list[DelegationLink] = Field(default_factory=list)


class Proof(BaseModel):
    """Cryptographic proof — the principal signs the envelope."""
    type: str = "Ed25519Signature2020"
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verification_method: str = ""  # e.g. "did:web:entripse.com#keys-1"
    proof_purpose: str = "assertionMethod"
    proof_value: str = ""  # base64-encoded signature


class Intent(BaseModel):
    """What the agent intends to do."""
    action: str
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class AgentIdentity(BaseModel):
    """Agent identity — the passport data."""
    id: str = Field(default_factory=lambda: f"did:web:localhost:agents:{uuid.uuid4().hex[:12]}")
    version: str = "1.0.0"
    runtime: str = "aip-sdk/0.1.0"
    attestation: Attestation = Field(default_factory=Attestation)


# ---------------------------------------------------------------------------
# Core Envelope
# ---------------------------------------------------------------------------

class IntentEnvelope(BaseModel):
    """
    The atomic unit of AIP-1.

    Every agent action carries a signed Intent Envelope containing:
    - Who the agent is (identity + attestation)
    - Who authorized it (principal + delegation chain)
    - What it wants to do (intent)
    - What it's allowed to do (boundaries)
    - Cryptographic proof that all of the above is legit
    """
    context: str = Field(default="https://aip.protocol/v1", alias="@context")
    type: str = Field(default="IntentEnvelope", alias="@type")
    protocol_version: str = "1.0.0"

    agent: AgentIdentity
    principal: Principal
    intent: Intent
    boundaries: Boundaries

    verification_tier: VerificationTier = VerificationTier.TIER_1
    entropy: str = Field(default_factory=lambda: f"nonce:{uuid.uuid4().hex}")
    ttl: int = Field(default=300, ge=1, le=86400)  # seconds
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None

    proof: Proof = Field(default_factory=Proof)

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Verification Result
# ---------------------------------------------------------------------------

class RevocationCheck(BaseModel):
    """Result of a revocation check."""
    status: RevocationStatus = RevocationStatus.NOT_REVOKED
    freshness: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    max_staleness_ms: int = 500
    confidence: str = "strong"


class VerificationResult(BaseModel):
    """
    The output of verify_intent() — structured, debuggable result.

    Every rejection carries an AIP error code so devs can debug.
    """
    valid: bool = False
    signature_valid: bool = False
    within_boundaries: bool = False
    attestation_match: bool = False
    revocation: RevocationCheck = Field(default_factory=RevocationCheck)
    trust_score: float = Field(default=0.0, ge=0.0, le=1.0)
    tier_used: VerificationTier = VerificationTier.TIER_1
    mandate_id: str | None = None  # set when a signed mandate governed this decision
    errors: list[AIPErrorCode] = Field(default_factory=list)
    detail: str = ""

    @property
    def revoked(self) -> bool:
        return self.revocation.status != RevocationStatus.NOT_REVOKED

    @property
    def passed(self) -> bool:
        return (
            self.valid
            and self.signature_valid
            and self.within_boundaries
            and self.attestation_match
            and not self.revoked
        )
