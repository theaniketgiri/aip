/**
 * AIP-1 Agent Intent Protocol — TypeScript Types
 *
 * These interfaces define the wire format for Intent Envelopes.
 * They mirror the Python Pydantic models exactly.
 */

// ── Enums ─────────────────────────────────────────────────────────

export type VerificationTier = "tier_0" | "tier_1" | "tier_2";
export type AttestationMethod = "self_reported" | "framework_registry" | "tee_hardware";
export type RevocationStatus = "not_revoked" | "revoked" | "suspended";

// ── Sub-models ────────────────────────────────────────────────────

export interface IntentClassifier {
  model: string;
  confidence_threshold: number;
}

export interface Attestation {
  method: AttestationMethod;
  framework_id: string | null;
  build_hash: string | null;
  system_prompt_hash: string | null;
  registry_signature: string | null;
  intent_classifier: IntentClassifier;
}

export interface MonetaryLimit {
  per_transaction: number;
  per_day: number;
  currency: string;
}

export interface TimeWindow {
  start: string;
  end: string;
}

export interface Boundaries {
  allowed_actions: string[];
  denied_actions: string[];
  monetary_limit: MonetaryLimit;
  data_access: string[];
  geo_restriction: string | null;
  time_window: TimeWindow | null;
}

export interface DelegationLink {
  from: string;
  to: string;
  scope: string;
  boundary_monotonicity: boolean;
  granted_at: string;
  expires_at: string | null;
}

export interface Principal {
  type: string;
  id: string;
  delegation_chain: DelegationLink[];
}

export interface Proof {
  type: string;
  created: string;
  verification_method: string;
  proof_purpose: string;
  proof_value: string;
}

export interface Intent {
  action: string;
  target: string;
  parameters: Record<string, unknown>;
}

export interface AgentIdentity {
  id: string;
  version: string;
  runtime: string;
  attestation: Attestation;
}

// ── Core Envelope ─────────────────────────────────────────────────

export interface IntentEnvelope {
  "@context": string;
  "@type": string;
  protocol_version: string;
  agent: AgentIdentity;
  principal: Principal;
  intent: Intent;
  boundaries: Boundaries;
  verification_tier: VerificationTier;
  entropy: string;
  ttl: number;
  issued_at: string;
  expires_at: string | null;
  proof: Proof;
}

// ── Error Codes ───────────────────────────────────────────────────

export enum AIPErrorCode {
  INVALID_SIGNATURE = "AIP-E100",
  EXPIRED_ENVELOPE = "AIP-E101",
  REPLAY_DETECTED = "AIP-E102",
  SCHEMA_INVALID = "AIP-E103",
  VERSION_UNSUPPORTED = "AIP-E104",
  NONCE_INVALID = "AIP-E105",

  ACTION_NOT_ALLOWED = "AIP-E200",
  ACTION_DENIED = "AIP-E201",
  MONETARY_LIMIT = "AIP-E202",
  TIME_WINDOW_VIOLATION = "AIP-E203",
  GEO_RESTRICTION = "AIP-E204",

  MODEL_HASH_MISMATCH = "AIP-E300",
  PROMPT_HASH_MISMATCH = "AIP-E301",
  FRAMEWORK_UNREGISTERED = "AIP-E302",
  INTENT_DRIFT = "AIP-E303",

  AGENT_REVOKED = "AIP-E400",
  AGENT_SUSPENDED = "AIP-E401",
  PRINCIPAL_REVOKED = "AIP-E402",
  DELEGATION_INVALID = "AIP-E403",
  TRUST_SCORE_LOW = "AIP-E404",

  MESH_UNAVAILABLE = "AIP-E500",
  REVOCATION_STALE = "AIP-E501",
  HANDSHAKE_TIMEOUT = "AIP-E502",
}

// ── Verification Result ───────────────────────────────────────────

export interface VerificationResult {
  valid: boolean;
  signature_valid: boolean;
  within_boundaries: boolean;
  attestation_match: boolean;
  tier_used: VerificationTier;
  errors: AIPErrorCode[];
  detail: string;
}

// ── Revocation ────────────────────────────────────────────────────

export interface RevocationRecord {
  agent_id: string;
  reason: string;
  revoked_at: string;
  revoked_by: string;
  scope: string;
  suspended_until: string | null;
}
