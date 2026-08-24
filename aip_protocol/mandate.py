"""
AIP Mandate — authorization the agent cannot widen.

THE PROBLEM THIS SOLVES

An Intent Envelope carries its own `boundaries`, and the agent signs the
envelope. The agent therefore signs its own cage. Nothing stops it from
declaring a wider one:

    passport.boundaries = Boundaries(allowed_actions=["transfer_funds"])
    verify_intent(sign_envelope(env, passport.private_key), ...)  # passes

RFC-001 §13.1 lists "boundary escalation" as mitigated because "modifying
boundaries invalidates the signature" — true for a third party in transit,
false for the agent, which holds the key.

THE FIX

Split the roles. The PRINCIPAL (payer, merchant, platform) signs a Mandate
with a key the agent never sees. The agent presents the mandate alongside
its envelope. The verifier checks the intent against the MANDATE's
boundaries and ignores whatever the envelope claims.

    mandate = issue_mandate(
        issuer="did:web:acme.com",
        subject=agent.agent_id,
        boundaries=Boundaries(allowed_actions=["pay"], ...),
        issuer_private_key=treasury_key,     # agent does not have this
    )
    verify_intent(envelope, agent.public_key,
                  mandate=mandate, issuer_public_key=treasury_pub)

The mandate travels beside the envelope rather than inside it, so adding
mandates does not change the canonical signable payload of an envelope and
existing signatures and conformance vectors stay valid. Both credentials are
independently signed: the envelope proves "this agent declared this intent",
the mandate proves "this principal granted this authority".
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field

from aip_protocol.crypto import sign_data, verify_signature
from aip_protocol.errors import AIPErrorCode
from aip_protocol.models import Boundaries, Proof

DEFAULT_MANDATE_TTL = timedelta(days=30)


class Mandate(BaseModel):
    """
    A signed grant of authority from a principal to an agent.

    The `proof` is produced by the ISSUER's key, not the agent's — that
    asymmetry is the entire security property.
    """
    context: str = Field(default="https://aip.protocol/v1", alias="@context")
    type: str = Field(default="Mandate", alias="@type")
    mandate_id: str = Field(default_factory=lambda: f"mandate:{uuid.uuid4().hex}")
    issuer: str
    subject: str
    boundaries: Boundaries
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    proof: Proof = Field(default_factory=Proof)

    model_config = {"populate_by_name": True}


def _signable_payload(mandate: Mandate) -> bytes:
    """
    Canonical bytes for a mandate, using the same rules as Intent Envelopes
    (RFC-001 §14.1): exclude the proof, sort keys, no whitespace, UTF-8.
    """
    from aip_protocol.envelope import _normalize_floats

    data = mandate.model_dump(mode="json", by_alias=True, exclude={"proof"})
    data = _normalize_floats(data)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def issue_mandate(
    issuer: str,
    subject: str,
    boundaries: Boundaries,
    issuer_private_key: Ed25519PrivateKey,
    ttl: timedelta | None = DEFAULT_MANDATE_TTL,
    issued_at: datetime | None = None,
) -> Mandate:
    """
    Issue a signed mandate granting `subject` the authority in `boundaries`.

    The signing key MUST belong to the issuer and MUST NOT be available to
    the agent — otherwise the agent can mint its own authority and this
    whole mechanism buys you nothing.
    """
    now = issued_at or datetime.now(timezone.utc)
    mandate = Mandate(
        issuer=issuer,
        subject=subject,
        boundaries=boundaries,
        issued_at=now,
        expires_at=(now + ttl) if ttl else None,
    )
    signature = sign_data(issuer_private_key, _signable_payload(mandate))
    return mandate.model_copy(update={"proof": Proof(
        type="Ed25519Signature2020",
        created=now,
        verification_method=f"{issuer}#keys-1",
        proof_purpose="assertionMethod",
        proof_value=signature,
    )})


def verify_mandate(
    mandate: Mandate,
    issuer_public_key: Ed25519PublicKey,
    subject: str,
    now: datetime | None = None,
) -> list[AIPErrorCode]:
    """
    Validate a mandate. Returns an empty list when it is good, otherwise the
    AIP error codes describing why it is not.
    """
    errors: list[AIPErrorCode] = []
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    if not verify_signature(issuer_public_key, _signable_payload(mandate), mandate.proof.proof_value):
        errors.append(AIPErrorCode.MANDATE_INVALID)
        return errors  # nothing else can be trusted

    if mandate.subject != subject:
        errors.append(AIPErrorCode.MANDATE_SUBJECT_MISMATCH)

    if mandate.expires_at is not None:
        expires = mandate.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if now > expires:
            errors.append(AIPErrorCode.MANDATE_EXPIRED)

    return errors
