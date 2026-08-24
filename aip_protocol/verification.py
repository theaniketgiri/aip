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

Tier-aware verification:
  Tier 0: HMAC cached check — <1ms (sig + boundaries only)
  Tier 1: Ed25519 signature + boundary + revocation — ~5ms
  Tier 2: Full verification with all 8 steps — ~50-100ms
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aip_protocol.crypto import verify_signature, hmac_verify
from aip_protocol.envelope import _get_signable_payload
from aip_protocol.errors import AIPError, AIPErrorCode
from aip_protocol.models import (
    Boundaries,
    IntentEnvelope,
    RevocationCheck,
    RevocationStatus,
    VerificationResult,
    VerificationTier,
)
from aip_protocol.ledger import SpendLedger
from aip_protocol.mandate import Mandate, verify_mandate
from aip_protocol.money import MoneyError, extract_amount_minor
from aip_protocol.revocation import RevocationStore
from aip_protocol.trust import TrustScoreEngine


# Default singletons for convenience
_default_revocation_store = RevocationStore()
_default_trust_engine = TrustScoreEngine()
_default_spend_ledger = SpendLedger()


SUPPORTED_VERSIONS = {"1.0.0"}

# AIP-1 §14.3: default lifetime for envelopes that omit expires_at.
DEFAULT_TTL_SECONDS = 300
PROTOCOL_VERSION = "1.0.0"


# ── Intent Classifier ─────────────────────────────────────────────────────

# Action similarity groups — actions in the same group are semantically related.
# This is the V1 lightweight classifier. V2 would use embeddings.
_ACTION_GROUPS: dict[str, set[str]] = {
    "financial": {"transfer_funds", "refund", "charge", "pay", "invoice", "billing", "payment", "withdraw", "deposit"},
    "data_read": {"read", "read_data", "read_invoice", "read_ticket", "view", "list", "get", "fetch", "query", "search"},
    "data_write": {"write", "write_data", "create", "update", "modify", "edit", "patch", "upsert"},
    "data_delete": {"delete", "remove", "purge", "drop", "destroy", "erase"},
    "notification": {"send_notification", "send_email", "notify", "alert", "send_message", "broadcast", "send"},
    "admin": {"admin", "configure", "modify_payroll", "access_hr_records", "manage_users", "set_permissions"},
    "order": {"create_order", "update_shipping", "send_invoice", "fulfill", "ship", "track"},
    "support": {"respond_ticket", "escalate", "resolve", "close_ticket", "assign"},
    "report": {"generate_report", "analyze", "summarize", "export", "dashboard"},
    "account": {"verify_account", "authenticate", "register", "login", "logout", "reset_password"},
}

# Build reverse index: action → group
_ACTION_TO_GROUP: dict[str, str] = {}
for _group, _actions in _ACTION_GROUPS.items():
    for _a in _actions:
        _ACTION_TO_GROUP[_a] = _group


def _classify_action_group(action: str) -> str | None:
    """Get the semantic group for an action."""
    # Exact match
    if action in _ACTION_TO_GROUP:
        return _ACTION_TO_GROUP[action]
    # Prefix match (e.g., "read_calendar" matches "read" → data_read)
    action_lower = action.lower()
    for prefix in sorted(_ACTION_TO_GROUP.keys(), key=len, reverse=True):
        if action_lower.startswith(prefix):
            return _ACTION_TO_GROUP[prefix]
    return None


def _check_intent_drift(envelope: IntentEnvelope, boundaries: 'Boundaries | None' = None) -> bool:
    """
    Lightweight intent classifier — checks if the action semantically
    aligns with the agent's allowed_actions.

    Returns True if action is within expected boundaries (no drift).
    Returns False if action is semantically outside the agent's scope.
    """
    action = envelope.intent.action
    allowed = (boundaries or envelope.boundaries).allowed_actions

    # If no allowed_actions defined, can't check drift
    if not allowed:
        return True

    # Exact match — always OK
    if action in allowed:
        return True

    # Get semantic group of the requested action
    action_group = _classify_action_group(action)
    if action_group is None:
        # Unknown action — can't classify, flag as drift
        return False

    # Check if ANY allowed action shares the same semantic group
    for allowed_action in allowed:
        allowed_group = _classify_action_group(allowed_action)
        if allowed_group == action_group:
            return True

    # Action's group doesn't match any allowed action's group → drift
    return False


# ── Main Verification Entry Point ─────────────────────────────────────────

def verify_intent(
    envelope: IntentEnvelope,
    public_key: Ed25519PublicKey,
    revocation_store: RevocationStore | None = None,
    trust_engine: TrustScoreEngine | None = None,
    min_trust_score: float = 0.0,
    registered_frameworks: set[str] | None = None,
    hmac_key: bytes | None = None,
    known_model_hashes: dict[str, str] | None = None,
    known_prompt_hashes: dict[str, str] | None = None,
    request_geo: str | None = None,
    max_revocation_staleness_ms: int | None = None,
    now: datetime | None = None,
    mandate: Mandate | None = None,
    issuer_public_key: Ed25519PublicKey | None = None,
    require_mandate: bool = False,
    spend_ledger: SpendLedger | None = None,
) -> VerificationResult:
    """
    Verify an Intent Envelope through the AIP handshake.

    The verification depth depends on the envelope's verification_tier:
      - Tier 0: Signature + boundaries only (fast path)
      - Tier 1: Signature + boundaries + revocation + attestation
      - Tier 2: Full pipeline including trust score, intent drift, delegation

    Args:
        envelope: The Intent Envelope to verify
        public_key: The principal's public key for signature verification
        revocation_store: Revocation store (uses default if None)
        trust_engine: Trust score engine (uses default if None)
        min_trust_score: Minimum trust score to accept (0.0 = accept all)
        registered_frameworks: Set of known framework DIDs (None = skip check)
        hmac_key: Shared HMAC key for Tier 0 fast-path (falls back to Ed25519)
        known_model_hashes: Map of framework_id → expected model hash
        known_prompt_hashes: Map of agent_id → expected prompt hash
        request_geo: ISO country code of the request origin (for geo check)
        max_revocation_staleness_ms: Override max staleness for revocation data
        now: Reference time for expiry/time-window checks. Defaults to the
            current UTC time; pass an explicit value for deterministic
            conformance testing or audit-log replay.
        mandate: Signed grant of authority from the principal. When present,
            its boundaries REPLACE the envelope's self-declared boundaries.
        issuer_public_key: Public key of the mandate issuer. Required to
            validate a mandate.
        require_mandate: Reject envelopes that arrive without a mandate
            (AIP-E405). Recommended for any cross-party deployment.
        spend_ledger: Rolling-window ledger used to enforce per_day limits.

    Returns:
        VerificationResult with all check results and any error codes
    """
    store = revocation_store or _default_revocation_store
    trust = trust_engine or _default_trust_engine
    errors: list[AIPErrorCode] = []
    tier = envelope.verification_tier

    result = VerificationResult(
        tier_used=tier,
    )

    # ─── Step 1: VERSION_CHECK (all tiers) ────────────────────────────
    if envelope.protocol_version not in SUPPORTED_VERSIONS:
        errors.append(AIPErrorCode.VERSION_UNSUPPORTED)
        return _fail(result, errors, "Unsupported protocol version")

    # ─── Step 2: SCHEMA_CHECK (all tiers) ─────────────────────────────
    # Pydantic validates schema on deserialization.
    # Additional structural checks:
    if not envelope.intent.action:
        errors.append(AIPErrorCode.SCHEMA_INVALID)
        return _fail(result, errors, "Intent envelope missing required action field")

    if not envelope.agent.id:
        errors.append(AIPErrorCode.SCHEMA_INVALID)
        return _fail(result, errors, "Intent envelope missing agent identity")

    # ─── Step 3: EXPIRY_CHECK (all tiers) ─────────────────────────────
    now = now if now is not None else datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    # AIP-1 §14.3: an envelope without expires_at is treated as expiring
    # DEFAULT_TTL_SECONDS after issue — absent expiry MUST NOT mean "never expires".
    expires = envelope.expires_at
    if expires is None:
        issued = envelope.issued_at
        if issued.tzinfo is None:
            issued = issued.replace(tzinfo=timezone.utc)
        expires = issued + timedelta(seconds=DEFAULT_TTL_SECONDS)
    elif expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if now > expires:
        errors.append(AIPErrorCode.EXPIRED_ENVELOPE)
        return _fail(result, errors, "Intent envelope has expired")

    # ─── Step 3b: NONCE_VALIDATION (all tiers) ──────────────────────
    # AIP-1 §10: Nonces MUST be at least 16 bytes of entropy.
    # Format: "nonce:<hex>" where hex is ≥32 characters (16 bytes).
    # This prevents weak nonces that make replay attacks trivial.
    nonce = envelope.entropy
    if not nonce or len(nonce) < 38:  # "nonce:" (6) + 32 hex chars = 38
        errors.append(AIPErrorCode.NONCE_INVALID)
        return _fail(result, errors, f"Nonce too short: {len(nonce) if nonce else 0} chars, minimum 38")

    # ─── Step 3c: REPLAY_CHECK (all tiers) ────────────────────────────
    if not store.check_nonce(nonce):
        errors.append(AIPErrorCode.REPLAY_DETECTED)
        return _fail(result, errors, "Nonce reuse detected — possible replay attack")

    # ─── Step 4: SIGNATURE_CHECK (tier-aware) ─────────────────────────
    payload = _get_signable_payload(envelope)

    if tier == VerificationTier.TIER_0 and hmac_key is not None:
        # Tier 0 fast path: HMAC verification (<1ms)
        sig_valid = hmac_verify(hmac_key, payload, envelope.proof.proof_value)
    else:
        # Tier 1 & 2: Ed25519 signature verification
        sig_valid = verify_signature(public_key, payload, envelope.proof.proof_value)

    if not sig_valid:
        errors.append(AIPErrorCode.INVALID_SIGNATURE)
        return _fail(result, errors, "Signature verification failed")

    result.signature_valid = True

    # ─── Step 4b: MANDATE_CHECK ───────────────────────────────────────
    # An envelope's own `boundaries` are signed by the agent, so an agent can
    # widen its own cage at will. A mandate is signed by the PRINCIPAL with a
    # key the agent does not hold, so it cannot be widened by the agent. When
    # one is present it is authoritative and the envelope's claim is ignored.
    effective_boundaries = envelope.boundaries

    if mandate is not None:
        if issuer_public_key is None:
            errors.append(AIPErrorCode.MANDATE_INVALID)
            return _fail(result, errors, "Mandate supplied without an issuer public key to verify it")
        mandate_errors = verify_mandate(mandate, issuer_public_key, envelope.agent.id, now=now)
        if mandate_errors:
            errors.extend(mandate_errors)
            trust.record_violation(envelope.agent.id)
            return _fail(result, errors, "Mandate verification failed")
        effective_boundaries = mandate.boundaries
        result.mandate_id = mandate.mandate_id
    elif require_mandate:
        errors.append(AIPErrorCode.MANDATE_REQUIRED)
        return _fail(result, errors, "Verifier requires a signed mandate; envelope carried none")

    # ─── Step 5: BOUNDARY_CHECK (all tiers) ───────────────────────────
    ledger = spend_ledger or _default_spend_ledger
    boundary_ok, boundary_errors, amount_minor = _check_boundaries(
        envelope, request_geo=request_geo, now=now,
        boundaries=effective_boundaries, spend_ledger=ledger,
    )
    if not boundary_ok:
        errors.extend(boundary_errors)
        result.within_boundaries = False
        trust.record_violation(envelope.agent.id)
        return _fail(result, errors, "Boundary violation")

    result.within_boundaries = True

    # ─── Step 5b: REVOCATION_CHECK (all tiers — security critical) ────
    # Revocation must be checked even on Tier 0 to prevent suspended/revoked
    # agents from bypassing the kill switch via the fast path.
    #
    # Staleness is enforced here too: a replica whose data has aged out cannot
    # prove an agent is un-revoked, so it fails CLOSED (AIP-E501) at every tier.
    # Checking this only at Tier 1+ would let the fast path trust stale data.
    staleness_budget_ms = max_revocation_staleness_ms or 500
    if not store.authoritative and store.last_sync_time is not None:
        age_ms = (now - store.last_sync_time).total_seconds() * 1000
        if age_ms > staleness_budget_ms:
            result.revocation = RevocationCheck(
                status=RevocationStatus.REVOKED,
                freshness=store.last_sync_time,
                max_staleness_ms=staleness_budget_ms,
                confidence="stale",
            )
            errors.append(AIPErrorCode.REVOCATION_STALE)
            return _fail(
                result, errors,
                f"Revocation data is stale ({age_ms:.0f}ms > {staleness_budget_ms}ms) — failing closed",
            )

    if store.is_revoked(envelope.agent.id):
        is_suspended = store.is_suspended(envelope.agent.id)
        if is_suspended:
            errors.append(AIPErrorCode.AGENT_SUSPENDED)
            return _fail(result, errors, "Agent is temporarily suspended")
        else:
            errors.append(AIPErrorCode.AGENT_REVOKED)
            return _fail(result, errors, "Agent has been revoked")

    # ═══ Tier 0 stops here — fast path complete ═══════════════════════
    if tier == VerificationTier.TIER_0:
        _record_spend(ledger, envelope, effective_boundaries, amount_minor, now)
        trust.record_success(envelope.agent.id)
        result.valid = True
        result.attestation_match = True  # N/A for Tier 0, mark as passed
        result.errors = []
        result.detail = "Tier 0 fast-path: signature + boundaries verified"
        return result

    # ─── Step 6: ATTESTATION_VERIFY (Tier 1 & 2) ─────────────────────
    attestation_ok, attestation_errors = _check_attestation(
        envelope, registered_frameworks,
        known_model_hashes=known_model_hashes,
        known_prompt_hashes=known_prompt_hashes,
    )
    if not attestation_ok:
        errors.extend(attestation_errors)
        result.attestation_match = False
        return _fail(result, errors, "Attestation verification failed")

    result.attestation_match = True

    # ─── Step 7: REVOCATION_CHECK (Tier 1 & 2) ────────────────────────
    revocation_check = _check_revocation(envelope, store, max_staleness_ms=staleness_budget_ms, now=now)
    result.revocation = revocation_check

    if revocation_check.status == RevocationStatus.REVOKED:
        if revocation_check.confidence == "stale":
            errors.append(AIPErrorCode.REVOCATION_STALE)
            return _fail(
                result, errors,
                f"Revocation data is stale (>{revocation_check.max_staleness_ms}ms) — failing closed",
            )
        errors.append(AIPErrorCode.AGENT_REVOKED)
        return _fail(result, errors, "Agent has been revoked")

    if revocation_check.status == RevocationStatus.SUSPENDED:
        errors.append(AIPErrorCode.AGENT_SUSPENDED)
        return _fail(result, errors, "Agent is temporarily suspended")

    # ═══ Tier 1 stops here — standard path complete ═══════════════════
    if tier == VerificationTier.TIER_1:
        _record_spend(ledger, envelope, effective_boundaries, amount_minor, now)
        trust.record_success(envelope.agent.id)
        result.valid = True
        result.errors = []
        result.detail = "Tier 1 standard: signature + boundaries + attestation + revocation verified"
        return result

    # ─── Step 7b: INTENT_DRIFT CHECK (Tier 2 only) ────────────────────
    if not _check_intent_drift(envelope, boundaries=effective_boundaries):
        errors.append(AIPErrorCode.INTENT_DRIFT)
        trust.record_violation(envelope.agent.id)
        return _fail(result, errors, f"Intent classifier flagged '{envelope.intent.action}' as outside declared boundaries")

    # ─── Step 7c: DELEGATION_CHECK (Tier 2 only) ──────────────────────
    delegation_ok, delegation_errors = _check_delegation(envelope, now=now)
    if not delegation_ok:
        errors.extend(delegation_errors)
        return _fail(result, errors, "Delegation chain validation failed")

    # ─── Step 8: TRUST_SCORE_CHECK (Tier 2 only) ──────────────────────
    score = trust.compute_score(envelope.agent.id)
    result.trust_score = score

    if min_trust_score > 0 and score < min_trust_score:
        history = trust.get_or_create(envelope.agent.id)
        if history.total_intents > 0:
            errors.append(AIPErrorCode.TRUST_SCORE_LOW)
            return _fail(result, errors, f"Trust score {score} below threshold {min_trust_score}")

    # ─── ALL CHECKS PASSED ────────────────────────────────────────────
    _record_spend(ledger, envelope, effective_boundaries, amount_minor, now)
    trust.record_success(envelope.agent.id)
    result.valid = True
    result.errors = []
    result.detail = "Tier 2 full: all 8 verification checks passed"
    return result


# ── Boundary Check ─────────────────────────────────────────────────────────

def _record_spend(ledger, envelope, boundaries, amount_minor, now) -> None:
    """Commit an authorized amount to the rolling ledger. Success paths only."""
    if amount_minor and boundaries.monetary_limit.per_day_minor > 0:
        ledger.record(
            envelope.agent.id, amount_minor,
            boundaries.monetary_limit.currency, now=now,
        )


def _check_boundaries(
    envelope: IntentEnvelope,
    request_geo: str | None = None,
    now: datetime | None = None,
    boundaries: "Boundaries | None" = None,
    spend_ledger: SpendLedger | None = None,
) -> tuple[bool, list[AIPErrorCode], int | None]:
    """
    Check the intent against the effective boundaries.

    Returns (ok, errors, amount_minor) — the amount is handed back so a
    caller can commit it to the spend ledger once the whole pipeline passes.
    """
    errors: list[AIPErrorCode] = []
    action = envelope.intent.action
    boundaries = boundaries if boundaries is not None else envelope.boundaries
    limit = boundaries.monetary_limit

    # Check denied actions first (deny takes precedence)
    if action in boundaries.denied_actions:
        errors.append(AIPErrorCode.ACTION_DENIED)

    # Check allowed actions
    if boundaries.allowed_actions and action not in boundaries.allowed_actions:
        errors.append(AIPErrorCode.ACTION_NOT_ALLOWED)

    # ── Monetary limits, in exact integer minor units ──
    try:
        amount_minor = extract_amount_minor(envelope.intent.parameters, limit.currency)
    except MoneyError:
        return False, [AIPErrorCode.SCHEMA_INVALID], None

    if amount_minor is not None:
        # Per-transaction cap (RFC §4.3)
        if limit.per_transaction_minor > 0 and amount_minor > limit.per_transaction_minor:
            errors.append(AIPErrorCode.MONETARY_LIMIT)

        # Cumulative rolling-window cap (RFC §4.3) — a per-txn cap alone is
        # defeated by splitting one payment into many.
        elif limit.per_day_minor > 0 and spend_ledger is not None:
            if spend_ledger.would_exceed(
                envelope.agent.id, amount_minor, limit.per_day_minor,
                limit.currency, now=now,
            ):
                errors.append(AIPErrorCode.MONETARY_LIMIT)

    # Check time window
    if boundaries.time_window is not None:
        now = now or datetime.now(timezone.utc)
        window = boundaries.time_window
        start = window.start if window.start.tzinfo else window.start.replace(tzinfo=timezone.utc)
        end = window.end if window.end.tzinfo else window.end.replace(tzinfo=timezone.utc)
        if now < start or now > end:
            errors.append(AIPErrorCode.TIME_WINDOW_VIOLATION)

    # Check geo restriction (AIP-E204)
    if boundaries.geo_restriction and request_geo:
        allowed_geos = {g.strip().upper() for g in boundaries.geo_restriction.split(",")}
        if request_geo.upper() not in allowed_geos:
            errors.append(AIPErrorCode.GEO_RESTRICTION)

    return len(errors) == 0, errors, amount_minor


# ── Attestation Check ──────────────────────────────────────────────────────

def _check_attestation(
    envelope: IntentEnvelope,
    registered_frameworks: set[str] | None = None,
    known_model_hashes: dict[str, str] | None = None,
    known_prompt_hashes: dict[str, str] | None = None,
) -> tuple[bool, list[AIPErrorCode]]:
    """Verify attestation claims."""
    errors: list[AIPErrorCode] = []
    attestation = envelope.agent.attestation

    # Framework registry check (AIP-E302)
    if attestation.method.value == "framework_registry":
        if registered_frameworks is not None:
            if attestation.framework_id and attestation.framework_id not in registered_frameworks:
                errors.append(AIPErrorCode.FRAMEWORK_UNREGISTERED)

    # Model hash verification (AIP-E300)
    if known_model_hashes and attestation.framework_id:
        expected_hash = known_model_hashes.get(attestation.framework_id)
        if expected_hash and attestation.build_hash:
            if attestation.build_hash != expected_hash:
                errors.append(AIPErrorCode.MODEL_HASH_MISMATCH)

    # Prompt hash verification (AIP-E301)
    if known_prompt_hashes and envelope.agent.id:
        expected_prompt = known_prompt_hashes.get(envelope.agent.id)
        if expected_prompt and attestation.system_prompt_hash:
            if attestation.system_prompt_hash != expected_prompt:
                errors.append(AIPErrorCode.PROMPT_HASH_MISMATCH)

    return len(errors) == 0, errors


# ── Delegation Check ───────────────────────────────────────────────────────

def _check_delegation(
    envelope: IntentEnvelope,
    now: datetime | None = None,
) -> tuple[bool, list[AIPErrorCode]]:
    """
    Validate the delegation chain from principal → agent.
    Checks: chain continuity, expiry, monotonicity.
    """
    errors: list[AIPErrorCode] = []
    chain = envelope.principal.delegation_chain

    if not chain:
        # No delegation chain — only valid if principal is the agent itself
        if envelope.principal.id != envelope.agent.id:
            errors.append(AIPErrorCode.DELEGATION_INVALID)
        return len(errors) == 0, errors

    now = now or datetime.now(timezone.utc)

    # Verify chain starts from the principal
    if chain[0].from_id != envelope.principal.id:
        errors.append(AIPErrorCode.DELEGATION_INVALID)
        return False, errors

    # Verify chain ends at the agent
    if chain[-1].to_id != envelope.agent.id:
        errors.append(AIPErrorCode.DELEGATION_INVALID)
        return False, errors

    # Walk the chain: each link's `to` must match the next link's `from`
    for i in range(len(chain) - 1):
        if chain[i].to_id != chain[i + 1].from_id:
            errors.append(AIPErrorCode.DELEGATION_INVALID)
            return False, errors

    # Check expiry on each link
    for link in chain:
        if link.expires_at is not None:
            expires = link.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if now > expires:
                errors.append(AIPErrorCode.DELEGATION_INVALID)
                return False, errors

    return len(errors) == 0, errors


# ── Revocation Check ───────────────────────────────────────────────────────

def _check_revocation(
    envelope: IntentEnvelope,
    store: RevocationStore,
    max_staleness_ms: int = 500,
    now: datetime | None = None,
) -> RevocationCheck:
    """Check agent's revocation status with freshness enforcement."""
    now = now or datetime.now(timezone.utc)

    # Check revocation data freshness (AIP-E501)
    # Staleness only applies to replica stores that mirror a remote registry.
    # An authoritative local store is never stale by definition.
    last_sync = store.last_sync_time
    if not store.authoritative and last_sync is not None:
        staleness_ms = (now - last_sync).total_seconds() * 1000
        if staleness_ms > max_staleness_ms:
            # Fail closed: we cannot prove the agent is un-revoked (AIP-E501).
            return RevocationCheck(
                status=RevocationStatus.REVOKED,
                freshness=last_sync,
                max_staleness_ms=max_staleness_ms,
                confidence="stale",
            )

    if store.is_revoked(envelope.agent.id):
        if store.is_suspended(envelope.agent.id):
            return RevocationCheck(
                status=RevocationStatus.SUSPENDED,
                freshness=now,
                max_staleness_ms=max_staleness_ms,
                confidence="strong",
            )
        return RevocationCheck(
            status=RevocationStatus.REVOKED,
            freshness=now,
            max_staleness_ms=max_staleness_ms,
            confidence="strong",
        )

    # Also check if principal is revoked (AIP-E402)
    if store.is_revoked(envelope.principal.id):
        return RevocationCheck(
            status=RevocationStatus.REVOKED,
            freshness=now,
            max_staleness_ms=max_staleness_ms,
            confidence="strong",
        )

    return RevocationCheck(
        status=RevocationStatus.NOT_REVOKED,
        freshness=now,
        max_staleness_ms=max_staleness_ms,
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
