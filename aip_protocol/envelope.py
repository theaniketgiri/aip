"""
AIP Envelope — Create and sign Intent Envelopes.

An Intent Envelope is the atomic unit of AIP-1. It wraps an agent's intent
with cryptographic proof that the intent is authorized.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aip_protocol.crypto import sign_data
from aip_protocol.models import (
    Intent,
    IntentEnvelope,
    MonetaryLimit,
    Proof,
    VerificationTier,
)
from aip_protocol.passport import AgentPassport


def _auto_select_tier(
    action: str,
    parameters: dict[str, Any],
    boundaries: Any,
    first_contact: bool = False,
    cross_org: bool = False,
) -> VerificationTier:
    """
    Auto-select verification tier based on risk.

    Tier 0: Low-risk, repeated actions within session
    Tier 1: Normal operations within boundaries
    Tier 2: High-value txns, cross-org, first contact
    """
    # Always Tier 2 for cross-org or first contact
    if cross_org or first_contact:
        return VerificationTier.TIER_2

    # Check for monetary value
    amount = parameters.get("amount", 0)
    if isinstance(amount, (int, float)) and amount > 100:
        return VerificationTier.TIER_2

    # Check for sensitive actions
    sensitive_actions = {"transfer_funds", "delete", "modify_payroll", "admin"}
    if action in sensitive_actions:
        return VerificationTier.TIER_1

    return VerificationTier.TIER_0


def create_envelope(
    passport: AgentPassport,
    action: str,
    target: str = "",
    parameters: dict[str, Any] | None = None,
    ttl: int = 300,
    tier: VerificationTier | None = None,
    first_contact: bool = False,
    cross_org: bool = False,
) -> IntentEnvelope:
    """
    Create an unsigned Intent Envelope from a passport and action.

    Args:
        passport: The agent's passport
        action: The action the agent intends to perform
        target: The target DID or URL
        parameters: Action parameters
        ttl: Time-to-live in seconds
        tier: Verification tier (auto-selected if None)
        first_contact: True if this is the first interaction with the verifier
        cross_org: True if this is a cross-organization request
    """
    parameters = parameters or {}

    # Auto-select tier if not specified
    if tier is None:
        tier = _auto_select_tier(
            action, parameters, passport.boundaries,
            first_contact=first_contact, cross_org=cross_org,
        )

    now = datetime.now(timezone.utc)

    envelope = IntentEnvelope(
        agent=passport.identity,
        principal=passport.principal,
        intent=Intent(
            action=action,
            target=target,
            parameters=parameters,
        ),
        boundaries=passport.boundaries,
        verification_tier=tier,
        ttl=ttl,
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )

    return envelope


def _normalize_floats(obj: Any) -> Any:
    """
    Normalize floats for cross-language canonical serialization.

    AIP-1 Canonical Rule:
      - Whole floats (500.0) MUST serialize as integers (500)
      - Non-whole floats (45.5) MUST serialize with minimal decimal places
      - This matches JavaScript's JSON.stringify behavior (RFC 7159 §6)

    Without this, Python serializes 500.0 → "500.0" while JavaScript
    serializes 500.0 → "500". Different bytes = different signature = broken.
    """
    if isinstance(obj, dict):
        return {k: _normalize_floats(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_normalize_floats(v) for v in obj]
    elif isinstance(obj, float):
        # If it's a whole number, convert to int for consistent serialization
        if obj == int(obj) and not (obj != obj):  # NaN check
            return int(obj)
        return obj
    return obj


def _get_signable_payload(envelope: IntentEnvelope) -> bytes:
    """
    Extract the canonical signable payload from an envelope.

    We sign everything except the proof itself (which would be circular).

    AIP-1 Canonical Serialization Rules:
      1. Exclude the "proof" field (circular)
      2. Normalize floats: whole numbers → integers (500.0 → 500)
      3. Sort keys recursively (json.dumps sort_keys=True)
      4. No whitespace (separators=(",", ":"))
      5. Encode as UTF-8 bytes

    These rules ensure byte-identical output across Python, JavaScript,
    Go, Rust, and any other JSON implementation.
    """
    data = envelope.model_dump(mode="json", by_alias=True, exclude={"proof"})
    data = _normalize_floats(data)
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return canonical.encode("utf-8")


def sign_envelope(
    envelope: IntentEnvelope,
    private_key: Ed25519PrivateKey,
    verification_method: str = "",
) -> IntentEnvelope:
    """
    Sign an Intent Envelope with the principal's private key.

    Returns a new envelope with the proof field populated.
    """
    payload = _get_signable_payload(envelope)
    signature = sign_data(private_key, payload)

    now = datetime.now(timezone.utc)
    proof = Proof(
        type="Ed25519Signature2020",
        created=now,
        verification_method=verification_method or f"{envelope.principal.id}#keys-1",
        proof_purpose="assertionMethod",
        proof_value=signature,
    )

    # Return a copy with the proof attached
    return envelope.model_copy(update={"proof": proof})


def envelope_to_json(envelope: IntentEnvelope, pretty: bool = True) -> str:
    """Serialize an envelope to JSON string."""
    data = envelope.model_dump(mode="json", by_alias=True)
    if pretty:
        return json.dumps(data, indent=2, default=str)
    return json.dumps(data, separators=(",", ":"), default=str)


def envelope_from_json(json_str: str) -> IntentEnvelope:
    """Deserialize an envelope from JSON string."""
    data = json.loads(json_str)
    return IntentEnvelope(**data)


def envelope_hash(envelope: IntentEnvelope) -> str:
    """Get the SHA-256 hash of an envelope's signable payload."""
    payload = _get_signable_payload(envelope)
    return hashlib.sha256(payload).hexdigest()
