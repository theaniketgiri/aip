"""
AIP Error Codes — Structured error taxonomy for the Agent Intent Protocol.

Error code ranges:
  AIP-E1xx: Envelope errors (signature, expiry, replay, schema)
  AIP-E2xx: Boundary violations (action, monetary, time, geo)
  AIP-E3xx: Attestation failures (model, prompt, framework, intent drift)
  AIP-E4xx: Trust failures (revoked, suspended, delegation, trust score)
  AIP-E5xx: Protocol errors (mesh unavailable, stale, timeout)
"""

from enum import Enum


class AIPErrorCode(str, Enum):
    """All AIP protocol error codes."""

    # E1xx — Envelope Errors
    INVALID_SIGNATURE = "AIP-E100"
    EXPIRED_ENVELOPE = "AIP-E101"
    REPLAY_DETECTED = "AIP-E102"
    SCHEMA_INVALID = "AIP-E103"
    VERSION_UNSUPPORTED = "AIP-E104"
    NONCE_INVALID = "AIP-E105"

    # E2xx — Boundary Violations
    ACTION_NOT_ALLOWED = "AIP-E200"
    ACTION_DENIED = "AIP-E201"
    MONETARY_LIMIT = "AIP-E202"
    TIME_WINDOW_VIOLATION = "AIP-E203"
    GEO_RESTRICTION = "AIP-E204"

    # E3xx — Attestation Failures
    MODEL_HASH_MISMATCH = "AIP-E300"
    PROMPT_HASH_MISMATCH = "AIP-E301"
    FRAMEWORK_UNREGISTERED = "AIP-E302"
    INTENT_DRIFT = "AIP-E303"

    # E4xx — Trust Failures
    AGENT_REVOKED = "AIP-E400"
    AGENT_SUSPENDED = "AIP-E401"
    PRINCIPAL_REVOKED = "AIP-E402"
    DELEGATION_INVALID = "AIP-E403"
    TRUST_SCORE_LOW = "AIP-E404"

    # E5xx — Protocol Errors
    MESH_UNAVAILABLE = "AIP-E500"
    REVOCATION_STALE = "AIP-E501"
    HANDSHAKE_TIMEOUT = "AIP-E502"


# Human-readable descriptions for each error code
ERROR_DESCRIPTIONS: dict[AIPErrorCode, str] = {
    AIPErrorCode.INVALID_SIGNATURE: "Cryptographic proof verification failed",
    AIPErrorCode.EXPIRED_ENVELOPE: "Intent envelope TTL has been exceeded",
    AIPErrorCode.REPLAY_DETECTED: "Entropy nonce has been reused — possible replay attack",
    AIPErrorCode.SCHEMA_INVALID: "Envelope does not conform to AIP-1 schema",
    AIPErrorCode.VERSION_UNSUPPORTED: "Protocol version is not supported by this verifier",
    AIPErrorCode.NONCE_INVALID: "Entropy nonce does not meet minimum format or length requirements (≥16 bytes)",
    AIPErrorCode.ACTION_NOT_ALLOWED: "Requested action is not in the agent's allowed_actions list",
    AIPErrorCode.ACTION_DENIED: "Requested action is explicitly in the agent's denied_actions list",
    AIPErrorCode.MONETARY_LIMIT: "Transaction amount exceeds per-transaction or per-day monetary limit",
    AIPErrorCode.TIME_WINDOW_VIOLATION: "Request is outside the agent's authorized time window",
    AIPErrorCode.GEO_RESTRICTION: "Request originates from a restricted geography",
    AIPErrorCode.MODEL_HASH_MISMATCH: "Model attestation hash does not match the registry",
    AIPErrorCode.PROMPT_HASH_MISMATCH: "System prompt template hash has changed",
    AIPErrorCode.FRAMEWORK_UNREGISTERED: "Agent framework is not registered in the attestation registry",
    AIPErrorCode.INTENT_DRIFT: "Intent classifier flagged action as outside declared boundaries",
    AIPErrorCode.AGENT_REVOKED: "Agent identity has been globally revoked",
    AIPErrorCode.AGENT_SUSPENDED: "Agent identity is temporarily suspended",
    AIPErrorCode.PRINCIPAL_REVOKED: "Principal organization has been revoked",
    AIPErrorCode.DELEGATION_INVALID: "Delegation chain is broken, expired, or violates monotonicity",
    AIPErrorCode.TRUST_SCORE_LOW: "Agent trust score is below verifier's minimum threshold",
    AIPErrorCode.MESH_UNAVAILABLE: "Cannot reach the AIP verification mesh",
    AIPErrorCode.REVOCATION_STALE: "Revocation data is older than the allowed max_staleness",
    AIPErrorCode.HANDSHAKE_TIMEOUT: "AIP verification handshake timed out",
}


class AIPError(Exception):
    """Base exception for AIP protocol errors."""

    def __init__(self, code: AIPErrorCode, detail: str | None = None):
        self.code = code
        self.description = ERROR_DESCRIPTIONS.get(code, "Unknown error")
        self.detail = detail or self.description
        super().__init__(f"[{code.value}] {self.detail}")

    def to_dict(self) -> dict:
        return {
            "error_code": self.code.value,
            "error_name": self.code.name,
            "description": self.description,
            "detail": self.detail,
        }
