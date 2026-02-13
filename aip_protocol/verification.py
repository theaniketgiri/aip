"""
AIP Verification Engine — The core of the protocol.

Implements the 8-step verification handshake:
  1. VERSION_CHECK
  2. SCHEMA_CHECK
  3. EXPIRY_CHECK
  4. BOUNDARY_CHECK
  5. ATTESTATION_VERIFY
  6. REVOCATION_CHECK
  7. TRUST_SCORE_CHECK
  8. RESULT (ACCEPT / REJECT with AIP error code)

Supports tiered verification:
  Tier 0: HMAC cached check — <1ms
  Tier 1: Ed25519 signature + boundary assertion — ~5ms
  Tier 2: Full verification with all checks — ~50-100ms
"""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aip_protocol.crypto import verify_signature
from aip_protocol.envelope import _get_signable_payload
from aip_protocol.errors import AIPError, AIPErrorCode
from aip_protocol.models import (
    IntentEnvelope,
    RevocationCheck,
    RevocationStatus,
    VerificationResult,
    VerificationTier,
)
from aip_protocol.revocation import RevocationStore
from aip_protocol.trust import TrustScoreEngine


# Default singletons for convenience
_default_revocation_store = RevocationStore()
_default_trust_engine = TrustScoreEngine()


SUPPORTED_VERSIONS = {"1.0.0"}
PROTOCOL_VERSION = "1.0.0"


def verify_intent(
    envelope: IntentEnvelope,
    public_key: Ed25519PublicKey,
    revocation_store: RevocationStore | None = None,
    trust_engine: TrustScoreEngine | None = None,
    min_trust_score: float = 0.0,
    registered_frameworks: set[str] | None = None,
) -> VerificationResult:
    """
    Verify an Intent Envelope through the full AIP handshake.

    This is the main entry point for verifiers. It runs all checks
    in sequence and returns a structured VerificationResult.

    Args:
        envelope: The Intent Envelope to verify
        public_key: The principal's public key for signature verification
        revocation_store: Revocation store (uses default if None)
        trust_engine: Trust score engine (uses default if None)
        min_trust_score: Minimum trust score to accept (0.0 = accept all)
        registered_frameworks: Set of known framework DIDs (None = skip check)

    Returns:
        VerificationResult with all check results and any error codes
    """
    store = revocation_store or _default_revocation_store
    trust = trust_engine or _default_trust_engine
    errors: list[AIPErrorCode] = []

    result = VerificationResult(
        tier_used=envelope.verification_tier,
    )

    # ─── Step 1: VERSION_CHECK ────────────────────────────────────────
    if envelope.protocol_version not in SUPPORTED_VERSIONS:
        errors.append(AIPErrorCode.VERSION_UNSUPPORTED)
        return _fail(result, errors, "Unsupported protocol version")

    # ─── Step 2: SCHEMA_CHECK ─────────────────────────────────────────
    # Pydantic already validates schema on deserialization.
    # If we got here, schema is valid.

    # ─── Step 3: EXPIRY_CHECK ─────────────────────────────────────────
    now = datetime.now(timezone.utc)

    if envelope.expires_at is not None:
        expires = envelope.expires_at
        # Handle naive datetimes by assuming UTC
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if now > expires:
            errors.append(AIPErrorCode.EXPIRED_ENVELOPE)
            return _fail(result, errors, "Intent envelope has expired")

    # ─── Step 3b: REPLAY_CHECK ────────────────────────────────────────
    if not store.check_nonce(envelope.entropy):
        errors.append(AIPErrorCode.REPLAY_DETECTED)
        return _fail(result, errors, "Nonce reuse detected — possible replay attack")

    # ─── Step 4: SIGNATURE_CHECK ──────────────────────────────────────
    payload = _get_signable_payload(envelope)
    sig_valid = verify_signature(public_key, payload, envelope.proof.proof_value)

    if not sig_valid:
        errors.append(AIPErrorCode.INVALID_SIGNATURE)
        return _fail(result, errors, "Ed25519 signature verification failed")

    result.signature_valid = True

    # ─── Step 5: BOUNDARY_CHECK ───────────────────────────────────────
    boundary_ok, boundary_errors = _check_boundaries(envelope)
    if not boundary_ok:
        errors.extend(boundary_errors)
        result.within_boundaries = False
        # Record violation in trust engine
        trust.record_violation(envelope.agent.id)
        return _fail(result, errors, "Boundary violation")

    result.within_boundaries = True

    # ─── Step 6: ATTESTATION_VERIFY ───────────────────────────────────
    attestation_ok, attestation_errors = _check_attestation(
        envelope, registered_frameworks
    )
    if not attestation_ok:
        errors.extend(attestation_errors)
        result.attestation_match = False
        return _fail(result, errors, "Attestation verification failed")

    result.attestation_match = True

    # ─── Step 7: REVOCATION_CHECK ─────────────────────────────────────
    revocation_check = _check_revocation(envelope, store)
    result.revocation = revocation_check

    if revocation_check.status == RevocationStatus.REVOKED:
        errors.append(AIPErrorCode.AGENT_REVOKED)
        return _fail(result, errors, "Agent has been revoked")

    if revocation_check.status == RevocationStatus.SUSPENDED:
        errors.append(AIPErrorCode.AGENT_SUSPENDED)
        return _fail(result, errors, "Agent is temporarily suspended")

    # ─── Step 8: TRUST_SCORE_CHECK ────────────────────────────────────
    score = trust.compute_score(envelope.agent.id)
    result.trust_score = score

    if min_trust_score > 0 and score < min_trust_score:
        history = trust.get_or_create(envelope.agent.id)
        # New agents with no history get a pass
        if history.total_intents > 0:
            errors.append(AIPErrorCode.TRUST_SCORE_LOW)
            return _fail(result, errors, f"Trust score {score} below threshold {min_trust_score}")

    # ─── ALL CHECKS PASSED ────────────────────────────────────────────
    trust.record_success(envelope.agent.id)
    result.valid = True
    result.errors = []
    result.detail = "All verification checks passed"
    return result


def _check_boundaries(
    envelope: IntentEnvelope,
) -> tuple[bool, list[AIPErrorCode]]:
    """Check if the intent is within the declared boundaries."""
    errors: list[AIPErrorCode] = []
    action = envelope.intent.action
    boundaries = envelope.boundaries

    # Check denied actions first (deny takes precedence)
    if action in boundaries.denied_actions:
        errors.append(AIPErrorCode.ACTION_DENIED)

    # Check allowed actions (if allow-list is defined, action must be in it)
    if boundaries.allowed_actions and action not in boundaries.allowed_actions:
        errors.append(AIPErrorCode.ACTION_NOT_ALLOWED)

    # Check monetary limits
    amount = envelope.intent.parameters.get("amount")
    if amount is not None and isinstance(amount, (int, float)):
        if boundaries.monetary_limit.per_transaction > 0:
            if amount > boundaries.monetary_limit.per_transaction:
                errors.append(AIPErrorCode.MONETARY_LIMIT)

    # Check time window
    if boundaries.time_window is not None:
        now = datetime.now(timezone.utc)
        window = boundaries.time_window
        start = window.start if window.start.tzinfo else window.start.replace(tzinfo=timezone.utc)
        end = window.end if window.end.tzinfo else window.end.replace(tzinfo=timezone.utc)
        if now < start or now > end:
            errors.append(AIPErrorCode.TIME_WINDOW_VIOLATION)

    return len(errors) == 0, errors


def _check_attestation(
    envelope: IntentEnvelope,
    registered_frameworks: set[str] | None = None,
) -> tuple[bool, list[AIPErrorCode]]:
    """Verify attestation claims."""
    errors: list[AIPErrorCode] = []
    attestation = envelope.agent.attestation

    # If framework registry method, check that framework is registered
    if attestation.method.value == "framework_registry":
        if registered_frameworks is not None:
            if attestation.framework_id and attestation.framework_id not in registered_frameworks:
                errors.append(AIPErrorCode.FRAMEWORK_UNREGISTERED)

    return len(errors) == 0, errors


def _check_revocation(
    envelope: IntentEnvelope,
    store: RevocationStore,
) -> RevocationCheck:
    """Check agent's revocation status."""
    now = datetime.now(timezone.utc)

    if store.is_revoked(envelope.agent.id):
        if store.is_suspended(envelope.agent.id):
            return RevocationCheck(
                status=RevocationStatus.SUSPENDED,
                freshness=now,
                confidence="strong",
            )
        return RevocationCheck(
            status=RevocationStatus.REVOKED,
            freshness=now,
            confidence="strong",
        )

    # Also check if principal is revoked
    if store.is_revoked(envelope.principal.id):
        return RevocationCheck(
            status=RevocationStatus.REVOKED,
            freshness=now,
            confidence="strong",
        )

    return RevocationCheck(
        status=RevocationStatus.NOT_REVOKED,
        freshness=now,
        confidence="strong",
    )


def _fail(
    result: VerificationResult,
    errors: list[AIPErrorCode],
    detail: str,
) -> VerificationResult:
    """Return a failed verification result."""
    result.errors = errors
    result.detail = detail
    result.valid = False
    return result
