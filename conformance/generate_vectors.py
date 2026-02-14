#!/usr/bin/env python3
"""
Generate deterministic test vectors for AIP-1 conformance testing.

This script generates JSON fixtures with known keys, signed envelopes,
and expected verification results. Any AIP-1 implementation in any
language must produce the same results for these vectors.

CRITICAL: We use the SDK's own _get_signable_payload() to ensure the
canonical JSON matches what the verifier will compute. The raw dict
form is then exported for cross-language consumption.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Add parent to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aip_protocol.models import (
    AgentIdentity,
    Attestation,
    Boundaries,
    DelegationLink,
    Intent,
    IntentEnvelope,
    MonetaryLimit,
    Principal,
    Proof,
    VerificationTier,
)
from aip_protocol.envelope import _get_signable_payload
from aip_protocol.crypto import sign_data


def _key_to_hex(private_key: Ed25519PrivateKey) -> dict:
    """Export key material as hex for cross-language reproducibility."""
    priv_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "private_key_hex": priv_bytes.hex(),
        "public_key_hex": pub_bytes.hex(),
        "public_key_b64": base64.urlsafe_b64encode(pub_bytes).decode(),
    }


def _hmac_sign(key: bytes, payload: bytes) -> str:
    """HMAC-SHA256 sign and return base64url-encoded."""
    digest = hmac.new(key, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode()


# ═══════════════════════════════════════════════════════════════════════════
# DETERMINISTIC SEED — All vectors derived from this
# ═══════════════════════════════════════════════════════════════════════════

SEED = bytes.fromhex("a" * 64)  # 32 bytes
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(SEED[:32])
KEY_INFO = _key_to_hex(PRIVATE_KEY)

SEED_2 = bytes.fromhex("b" * 64)
PRIVATE_KEY_2 = Ed25519PrivateKey.from_private_bytes(SEED_2[:32])
KEY_INFO_2 = _key_to_hex(PRIVATE_KEY_2)

HMAC_KEY = bytes.fromhex("c" * 64)

# Fixed timestamps
T_NOW_STR = "2026-02-14T12:00:00+00:00"
T_NOW = datetime.fromisoformat(T_NOW_STR)
T_EXPIRED = datetime.fromisoformat("2024-01-01T00:00:00+00:00")  # Always in the past


def make_envelope(
    action="transfer_funds",
    amount=200.0,
    tier=VerificationTier.TIER_1,
    nonce="nonce:aabbccdd11223344aabbccdd11223344",
    expires_at=None,
    allowed_actions=None,
    denied_actions=None,
    monetary_limit=500.0,
    geo_restriction=None,
) -> IntentEnvelope:
    """Build a proper Pydantic IntentEnvelope."""
    return IntentEnvelope(
        agent=AgentIdentity(
            id="did:web:acme.com:agents:procurement-bot",
            version="1.0.0",
            runtime="aip-sdk/0.1.0",
            attestation=Attestation(
                method="self_reported",
                framework_id=None,
                build_hash=None,
                system_prompt_hash=None,
                registry_signature=None,
            ),
        ),
        principal=Principal(
            type="organization",
            id="did:web:acme.com",
            delegation_chain=[
                DelegationLink(
                    **{
                        "from": "did:web:acme.com",
                        "to": "did:web:acme.com:agents:procurement-bot",
                        "scope": "default",
                        "boundary_monotonicity": True,
                        "granted_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                        "expires_at": None,
                    }
                ),
            ],
        ),
        intent=Intent(
            action=action,
            target="did:web:vendor.com:agents:billing",
            parameters={"amount": amount, "currency": "USD"},
        ),
        boundaries=Boundaries(
            allowed_actions=allowed_actions or ["transfer_funds", "read_invoice"],
            denied_actions=denied_actions or [],
            monetary_limit=MonetaryLimit(
                per_transaction=monetary_limit,
                per_day=5000.0,
                currency="USD",
            ),
            data_access=[],
            geo_restriction=geo_restriction,
            time_window=None,
        ),
        verification_tier=tier,
        entropy=nonce,
        ttl=300,
        issued_at=T_NOW,
        expires_at=expires_at,
    )


def sign_env(envelope: IntentEnvelope, key=PRIVATE_KEY) -> IntentEnvelope:
    """Sign using the SDK's own canonical serialization path."""
    payload = _get_signable_payload(envelope)
    sig = sign_data(key, payload)  # returns base64url string

    proof = Proof(
        type="Ed25519Signature2020",
        created=T_NOW,
        verification_method=f"{envelope.principal.id}#keys-1",
        proof_purpose="assertionMethod",
        proof_value=sig,
    )
    return envelope.model_copy(update={"proof": proof})


def hmac_sign_env(envelope: IntentEnvelope, key=HMAC_KEY) -> IntentEnvelope:
    """Sign with HMAC using the SDK's canonical serialization path."""
    payload = _get_signable_payload(envelope)
    sig = _hmac_sign(key, payload)

    proof = Proof(
        type="Ed25519Signature2020",
        created=T_NOW,
        verification_method=f"{envelope.principal.id}#keys-1",
        proof_purpose="assertionMethod",
        proof_value=sig,
    )
    return envelope.model_copy(update={"proof": proof})


def to_dict(envelope: IntentEnvelope) -> dict:
    """Export envelope to a cross-language JSON dict."""
    return envelope.model_dump(mode="json", by_alias=True)


# ═══════════════════════════════════════════════════════════════════════════
# GENERATE ALL TEST VECTORS
# ═══════════════════════════════════════════════════════════════════════════

_n = 0


def nonce() -> str:
    global _n
    _n += 1
    return f"nonce:{_n:032x}"


vectors = {
    "_meta": {
        "spec_version": "AIP-1",
        "generated_at": T_NOW_STR,
        "description": (
            "AIP-1 Conformance Test Vectors. Any compliant implementation "
            "MUST produce identical verification results for these inputs."
        ),
        "key_material": {
            "agent_1": KEY_INFO,
            "agent_2": KEY_INFO_2,
            "hmac_key_hex": HMAC_KEY.hex(),
        },
        "canonical_serialization": (
            "Signable payload = model_dump(mode='json', by_alias=True, exclude={'proof'}) "
            "-> json.dumps(sort_keys=True, separators=(',', ':')) -> UTF-8 bytes"
        ),
    },
}


# ─── CATEGORY A: Envelope Validity ───────────────────────────────

e = sign_env(make_envelope(nonce=nonce()))
vectors["A01_valid_envelope"] = {
    "description": "A correctly formed and signed envelope MUST pass verification.",
    "category": "envelope_validity",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": True, "signature_valid": True, "within_boundaries": True, "errors": []},
}

e = sign_env(make_envelope(nonce=nonce(), expires_at=T_EXPIRED))
vectors["A02_expired_envelope"] = {
    "description": "An envelope whose expires_at is in the past MUST be rejected with AIP-E101.",
    "category": "envelope_validity",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": False, "errors": ["AIP-E101"]},
}

e_bad_ver = make_envelope(nonce=nonce())
e_bad_ver = e_bad_ver.model_copy(update={"protocol_version": "99.0.0"})
e_bad_ver = sign_env(e_bad_ver)
vectors["A03_wrong_version"] = {
    "description": "An envelope with an unsupported protocol_version MUST be rejected with AIP-E104.",
    "category": "envelope_validity",
    "envelope": to_dict(e_bad_ver),
    "verify_with": "agent_1",
    "expected": {"valid": False, "errors": ["AIP-E104"]},
}

e = sign_env(make_envelope(action="", nonce=nonce()))
vectors["A04_missing_action"] = {
    "description": "An envelope with an empty action field MUST be rejected with AIP-E103.",
    "category": "envelope_validity",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": False, "errors": ["AIP-E103"]},
}


# ─── CATEGORY B: Signature Verification ──────────────────────────

e = sign_env(make_envelope(nonce=nonce()))
vectors["B01_valid_signature"] = {
    "description": "An envelope signed by the correct private key MUST pass signature verification.",
    "category": "signature",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": True, "signature_valid": True},
}

e = sign_env(make_envelope(nonce=nonce()))
vectors["B02_wrong_public_key"] = {
    "description": "An envelope verified with the wrong public key MUST fail with AIP-E100.",
    "category": "signature",
    "envelope": to_dict(e),
    "verify_with": "agent_2",
    "expected": {"valid": False, "signature_valid": False, "errors": ["AIP-E100"]},
}

e_tampered = sign_env(make_envelope(nonce=nonce()))
d = to_dict(e_tampered)
d["intent"]["action"] = "delete_everything"
vectors["B03_tampered_payload"] = {
    "description": "An envelope whose payload was modified after signing MUST fail with AIP-E100.",
    "category": "signature",
    "envelope": d,
    "verify_with": "agent_1",
    "expected": {"valid": False, "signature_valid": False, "errors": ["AIP-E100"]},
}

e = hmac_sign_env(make_envelope(tier=VerificationTier.TIER_0, nonce=nonce()))
vectors["B04_hmac_tier0_valid"] = {
    "description": "A Tier 0 envelope with valid HMAC-SHA256 signature MUST pass verification when the verifier has the shared key.",
    "category": "signature",
    "envelope": to_dict(e),
    "verify_with": "hmac",
    "expected": {"valid": True, "signature_valid": True},
}


# ─── CATEGORY C: Replay Detection ────────────────────────────────

e = sign_env(make_envelope(nonce=nonce()))
vectors["C01_unique_nonce_passes"] = {
    "description": "An envelope with a nonce never seen before MUST pass replay detection.",
    "category": "replay",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": True},
}

e = sign_env(make_envelope(nonce=nonce()))
vectors["C02_duplicate_nonce_fails"] = {
    "description": "An envelope with a nonce that has already been verified MUST be rejected with AIP-E102.",
    "category": "replay",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "verify_twice": True,
    "expected_first": {"valid": True},
    "expected": {"valid": False, "errors": ["AIP-E102"]},
}


# ─── CATEGORY D: Boundary Enforcement ────────────────────────────

e = sign_env(make_envelope(action="read_invoice", amount=0, nonce=nonce()))
vectors["D01_allowed_action_passes"] = {
    "description": "An action in allowed_actions MUST pass boundary check.",
    "category": "boundary",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": True, "within_boundaries": True},
}

e = sign_env(make_envelope(action="delete_database", amount=0, nonce=nonce()))
vectors["D02_disallowed_action_fails"] = {
    "description": "An action NOT in allowed_actions MUST be rejected with AIP-E200.",
    "category": "boundary",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": False, "within_boundaries": False, "errors": ["AIP-E200"]},
}

e = sign_env(make_envelope(
    action="transfer_funds", amount=100,
    denied_actions=["transfer_funds"], nonce=nonce(),
))
vectors["D03_denied_action_fails"] = {
    "description": "An action in denied_actions MUST be rejected with AIP-E201, even if also in allowed_actions.",
    "category": "boundary",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": False, "within_boundaries": False, "errors": ["AIP-E201"]},
}

e = sign_env(make_envelope(amount=500.0, monetary_limit=500.0, nonce=nonce()))
vectors["D04_monetary_limit_exact_passes"] = {
    "description": "An amount exactly equal to per_transaction limit MUST pass.",
    "category": "boundary",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": True, "within_boundaries": True},
}

e = sign_env(make_envelope(amount=15000.0, monetary_limit=500.0, nonce=nonce()))
vectors["D05_monetary_limit_exceeded"] = {
    "description": "An amount exceeding per_transaction limit MUST be rejected with AIP-E202.",
    "category": "boundary",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": False, "within_boundaries": False, "errors": ["AIP-E202"]},
}

e = sign_env(make_envelope(geo_restriction="US", nonce=nonce()))
vectors["D06_geo_restriction_match_passes"] = {
    "description": "A request from a matching geography MUST pass geo check.",
    "category": "boundary",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "request_geo": "US",
    "expected": {"valid": True, "within_boundaries": True},
}

e = sign_env(make_envelope(geo_restriction="US", nonce=nonce()))
vectors["D07_geo_restriction_mismatch_fails"] = {
    "description": "A request from a non-matching geography MUST be rejected with AIP-E204.",
    "category": "boundary",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "request_geo": "RU",
    "expected": {"valid": False, "within_boundaries": False, "errors": ["AIP-E204"]},
}


# ─── CATEGORY E: Revocation ──────────────────────────────────────

e = sign_env(make_envelope(nonce=nonce()))
vectors["E01_non_revoked_passes"] = {
    "description": "An agent that is not revoked MUST pass revocation check.",
    "category": "revocation",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "revocations": [],
    "expected": {"valid": True},
}

e = sign_env(make_envelope(nonce=nonce()))
vectors["E02_revoked_agent_fails"] = {
    "description": "A revoked agent MUST be rejected with AIP-E400 at ALL tiers including Tier 0.",
    "category": "revocation",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "revocations": [{
        "agent_id": "did:web:acme.com:agents:procurement-bot",
        "reason": "compromised_key",
        "revoked_at": "2026-02-14T11:30:00+00:00",
        "revoked_by": "did:web:acme.com",
        "scope": "global",
        "suspended_until": None,
    }],
    "expected": {"valid": False, "errors": ["AIP-E400"]},
}

e = sign_env(make_envelope(tier=VerificationTier.TIER_0, nonce=nonce()))
vectors["E03_revoked_at_tier0"] = {
    "description": "A revoked agent MUST be rejected even on Tier 0 fast path. Revocation MUST NOT be bypassed by tier selection.",
    "category": "revocation",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "revocations": [{
        "agent_id": "did:web:acme.com:agents:procurement-bot",
        "reason": "anomalous_behavior",
        "revoked_at": "2026-02-14T11:30:00+00:00",
        "revoked_by": "did:web:acme.com",
        "scope": "global",
        "suspended_until": None,
    }],
    "expected": {"valid": False, "errors": ["AIP-E400"]},
}

e = sign_env(make_envelope(nonce=nonce()))
vectors["E04_suspended_agent_fails"] = {
    "description": "A suspended agent MUST be rejected with AIP-E401.",
    "category": "revocation",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "revocations": [{
        "agent_id": "did:web:acme.com:agents:procurement-bot",
        "reason": "under_review",
        "revoked_at": "2026-02-14T11:30:00+00:00",
        "revoked_by": "did:web:acme.com",
        "scope": "global",
        "suspended_until": "2099-12-31T23:59:59+00:00",
    }],
    "expected": {"valid": False, "errors": ["AIP-E401"]},
}


# ─── CATEGORY F: Tiered Verification Behavior ────────────────────

e = sign_env(make_envelope(tier=VerificationTier.TIER_0, nonce=nonce()))
vectors["F01_tier0_skips_attestation"] = {
    "description": "Tier 0 verification MUST NOT check attestation. A valid Tier 0 envelope MUST pass even with no attestation data.",
    "category": "tiered",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": True, "tier_used": "tier_0"},
}

e = sign_env(make_envelope(tier=VerificationTier.TIER_0, nonce=nonce()))
vectors["F02_tier_escalation_allowed"] = {
    "description": "A verifier MAY escalate verification tier. A Tier 0 envelope verified at Tier 1 MUST still pass if all checks succeed.",
    "category": "tiered",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "escalate_to": "tier_1",
    "expected": {"valid": True},
}


# ─── CATEGORY G: Edge Cases ──────────────────────────────────────

e = sign_env(make_envelope(amount=0.0, nonce=nonce()))
vectors["G01_zero_amount_passes"] = {
    "description": "A zero-amount transaction MUST pass monetary boundary check.",
    "category": "edge_case",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": True, "within_boundaries": True},
}

e = sign_env(make_envelope(amount=-50.0, nonce=nonce()))
vectors["G02_negative_amount_passes"] = {
    "description": "A negative amount (refund) MUST pass monetary boundary check.",
    "category": "edge_case",
    "envelope": to_dict(e),
    "verify_with": "agent_1",
    "expected": {"valid": True, "within_boundaries": True},
}


# ─── Write output ────────────────────────────────────────────────

if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "vectors.json")

    # Also export the canonical payload for A01 as a reference
    a01_env = IntentEnvelope.model_validate(vectors["A01_valid_envelope"]["envelope"])
    canonical = _get_signable_payload(a01_env)
    vectors["_meta"]["reference_canonical_payload_hex"] = canonical.hex()

    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2, default=str)

    test_count = sum(1 for k in vectors if not k.startswith("_"))
    categories = set(v.get("category", "") for k, v in vectors.items() if not k.startswith("_"))

    print(f"Generated {test_count} test vectors across {len(categories)} categories")
    print(f"Categories: {', '.join(sorted(categories))}")
    print(f"Output: {out_path}")
