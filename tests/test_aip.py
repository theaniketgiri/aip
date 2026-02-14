"""
AIP Protocol — Comprehensive Test Suite

Tests cover:
  1. Crypto layer (key gen, signing, verification, HMAC)
  2. Passport lifecycle (create, save, load)
  3. Envelope creation and signing
  4. Tiered verification (tier-aware pipeline)
  5. Boundary enforcement (incl. geo restriction)
  6. Revocation, suspension, rehydration
  7. Replay detection
  8. Trust scoring
  9. Intent classifier / drift detection
  10. Attestation (model hash, prompt hash, framework)
  11. Delegation chain validation
  12. Error taxonomy (all codes wired)
  13. Full integration flow
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aip_protocol.crypto import (
    generate_keypair,
    sign_data,
    verify_signature,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    public_key_to_b64,
    b64_to_public_key,
    generate_hmac_key,
    hmac_sign,
    hmac_verify,
)
from aip_protocol.passport import AgentPassport
from aip_protocol.envelope import (
    create_envelope,
    sign_envelope,
    envelope_to_json,
    envelope_from_json,
    envelope_hash,
    _get_signable_payload,
)
from aip_protocol.verification import (
    verify_intent,
    _check_intent_drift,
    _classify_action_group,
)
from aip_protocol.revocation import RevocationStore
from aip_protocol.trust import TrustScoreEngine
from aip_protocol.errors import AIPError, AIPErrorCode
from aip_protocol.models import (
    IntentEnvelope,
    VerificationTier,
    RevocationStatus,
    DelegationLink,
)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Crypto Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCrypto:
    def test_keypair_generation(self):
        private, public = generate_keypair()
        assert private is not None
        assert public is not None

    def test_sign_and_verify(self):
        private, public = generate_keypair()
        data = b"hello aip protocol"
        sig = sign_data(private, data)
        assert verify_signature(public, data, sig) is True

    def test_invalid_signature_fails(self):
        private, public = generate_keypair()
        data = b"hello aip protocol"
        sig = sign_data(private, data)
        # Tamper with data
        assert verify_signature(public, b"tampered data", sig) is False

    def test_wrong_key_fails(self):
        private1, public1 = generate_keypair()
        _, public2 = generate_keypair()
        data = b"hello"
        sig = sign_data(private1, data)
        assert verify_signature(public2, data, sig) is False

    def test_key_serialization_pem(self):
        private, public = generate_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path = Path(tmpdir) / "private.pem"
            pub_path = Path(tmpdir) / "public.pem"
            save_private_key(private, priv_path)
            save_public_key(public, pub_path)

            loaded_priv = load_private_key(priv_path)
            loaded_pub = load_public_key(pub_path)

            # Verify loaded keys work
            data = b"roundtrip test"
            sig = sign_data(loaded_priv, data)
            assert verify_signature(loaded_pub, data, sig) is True

    def test_key_serialization_b64(self):
        _, public = generate_keypair()
        b64 = public_key_to_b64(public)
        restored = b64_to_public_key(b64)
        # Compare raw bytes
        assert public_key_to_b64(restored) == b64

    def test_hmac_sign_and_verify(self):
        key = generate_hmac_key()
        data = b"tier 0 fast path data"
        sig = hmac_sign(key, data)
        assert hmac_verify(key, data, sig) is True

    def test_hmac_wrong_key_fails(self):
        key1 = generate_hmac_key()
        key2 = generate_hmac_key()
        data = b"test data"
        sig = hmac_sign(key1, data)
        assert hmac_verify(key2, data, sig) is False

    def test_hmac_tampered_data_fails(self):
        key = generate_hmac_key()
        sig = hmac_sign(key, b"original")
        assert hmac_verify(key, b"tampered", sig) is False


# ══════════════════════════════════════════════════════════════════════════════
# 2. Passport Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestPassport:
    def test_create_passport(self):
        passport = AgentPassport.create(
            domain="test.com",
            agent_name="test-bot",
            allowed_actions=["read", "write"],
            monetary_limit_per_txn=100.0,
        )
        assert passport.agent_id == "did:web:test.com:agents:test-bot"
        assert passport.principal.id == "did:web:test.com"
        assert "read" in passport.boundaries.allowed_actions
        assert passport.boundaries.monetary_limit.per_transaction == 100.0

    def test_save_and_load(self):
        passport = AgentPassport.create(
            domain="entripse.com",
            agent_name="procurement-v1",
            allowed_actions=["transfer_funds"],
            monetary_limit_per_txn=50.0,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            passport.save(tmpdir)
            loaded = AgentPassport.load(tmpdir)

            assert loaded.agent_id == passport.agent_id
            assert loaded.principal.id == passport.principal.id
            assert loaded.boundaries.allowed_actions == passport.boundaries.allowed_actions

            # Verify key roundtrip
            data = b"key roundtrip"
            sig = sign_data(loaded.private_key, data)
            assert verify_signature(loaded.public_key, data, sig) is True

    def test_auto_generated_name(self):
        passport = AgentPassport.create(domain="test.com")
        assert passport.agent_id.startswith("did:web:test.com:agents:")


# ══════════════════════════════════════════════════════════════════════════════
# 3. Envelope Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestEnvelope:
    def _create_passport(self):
        return AgentPassport.create(
            domain="test.com",
            agent_name="test-bot",
            allowed_actions=["read_data", "transfer_funds", "send_notification"],
            monetary_limit_per_txn=100.0,
            monetary_limit_per_day=1000.0,
        )

    def test_create_envelope(self):
        passport = self._create_passport()
        env = create_envelope(passport, action="read_data")
        assert env.intent.action == "read_data"
        assert env.agent.id == passport.agent_id
        assert env.protocol_version == "1.0.0"

    def test_auto_tier_selection_low_risk(self):
        passport = self._create_passport()
        env = create_envelope(passport, action="read_data")
        assert env.verification_tier == VerificationTier.TIER_0

    def test_auto_tier_selection_monetary(self):
        passport = self._create_passport()
        env = create_envelope(
            passport,
            action="transfer_funds",
            parameters={"amount": 500},
        )
        assert env.verification_tier == VerificationTier.TIER_2

    def test_auto_tier_cross_org(self):
        passport = self._create_passport()
        env = create_envelope(passport, action="read_data", cross_org=True)
        assert env.verification_tier == VerificationTier.TIER_2

    def test_sign_envelope(self):
        passport = self._create_passport()
        env = create_envelope(passport, action="read_data")
        signed = sign_envelope(env, passport.private_key)
        assert signed.proof.proof_value != ""
        assert signed.proof.type == "Ed25519Signature2020"

    def test_envelope_serialization(self):
        passport = self._create_passport()
        env = create_envelope(passport, action="read_data")
        signed = sign_envelope(env, passport.private_key)

        json_str = envelope_to_json(signed)
        restored = envelope_from_json(json_str)

        assert restored.intent.action == "read_data"
        assert restored.proof.proof_value == signed.proof.proof_value

    def test_envelope_hash_deterministic(self):
        passport = self._create_passport()
        env = create_envelope(passport, action="read_data")
        h1 = envelope_hash(env)
        h2 = envelope_hash(env)
        assert h1 == h2


# ══════════════════════════════════════════════════════════════════════════════
# 4. Verification Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestVerification:
    def _signed_setup(self, action="read_data", params=None):
        passport = AgentPassport.create(
            domain="test.com",
            agent_name="verif-bot",
            allowed_actions=["read_data", "transfer_funds"],
            monetary_limit_per_txn=100.0,
        )
        env = create_envelope(
            passport, action=action,
            parameters=params or {},
        )
        signed = sign_envelope(env, passport.private_key)
        return passport, signed

    def test_valid_intent_passes(self):
        passport, signed = self._signed_setup()
        store = RevocationStore()
        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is True
        assert result.signature_valid is True
        assert result.within_boundaries is True
        assert len(result.errors) == 0

    def test_invalid_signature_fails(self):
        passport, signed = self._signed_setup()
        _, other_public = generate_keypair()
        store = RevocationStore()
        result = verify_intent(signed, other_public, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.INVALID_SIGNATURE in result.errors

    def test_denied_action_fails(self):
        passport = AgentPassport.create(
            domain="test.com",
            agent_name="deny-bot",
            allowed_actions=["read_data"],
            denied_actions=["delete_everything"],
        )
        env = create_envelope(passport, action="delete_everything")
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()
        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.ACTION_DENIED in result.errors

    def test_action_not_allowed_fails(self):
        passport = AgentPassport.create(
            domain="test.com",
            agent_name="limited-bot",
            allowed_actions=["read_data"],
        )
        env = create_envelope(passport, action="write_data")
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()
        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.ACTION_NOT_ALLOWED in result.errors

    def test_monetary_limit_exceeded(self):
        passport = AgentPassport.create(
            domain="test.com",
            agent_name="money-bot",
            allowed_actions=["transfer_funds"],
            monetary_limit_per_txn=50.0,
        )
        env = create_envelope(
            passport, action="transfer_funds",
            parameters={"amount": 200.0},
        )
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()
        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.MONETARY_LIMIT in result.errors

    def test_expired_envelope_fails(self):
        passport, signed = self._signed_setup()
        # Manually set expiry to the past
        signed = signed.model_copy(update={
            "expires_at": datetime.now(timezone.utc) - timedelta(seconds=60)
        })
        store = RevocationStore()
        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.EXPIRED_ENVELOPE in result.errors

    def test_revoked_agent_fails(self):
        passport = AgentPassport.create(
            domain="test.com", agent_name="revoked-bot",
            allowed_actions=["read_data"],
        )
        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_1)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()
        store.revoke(passport.agent_id, reason="test_revocation")
        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.AGENT_REVOKED in result.errors

    def test_suspended_agent_fails(self):
        passport = AgentPassport.create(
            domain="test.com", agent_name="suspended-bot",
            allowed_actions=["read_data"],
        )
        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_1)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()
        store.suspend(passport.agent_id, duration_seconds=3600)
        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.AGENT_SUSPENDED in result.errors

    def test_replay_detection(self):
        passport, signed = self._signed_setup()
        store = RevocationStore()

        # First verification should pass
        result1 = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result1.passed is True

        # Replayed envelope should fail
        result2 = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result2.passed is False
        assert AIPErrorCode.REPLAY_DETECTED in result2.errors

    def test_unregistered_framework_fails(self):
        passport = AgentPassport.create(
            domain="test.com",
            agent_name="fw-bot",
            allowed_actions=["read_data"],
            framework_id="did:web:unknown-framework.com",
        )
        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_1)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(
            signed,
            passport.public_key,
            revocation_store=store,
            registered_frameworks={"did:web:langchain.com", "did:web:crewai.com"},
        )
        assert result.passed is False
        assert AIPErrorCode.FRAMEWORK_UNREGISTERED in result.errors


# ══════════════════════════════════════════════════════════════════════════════
# 5. Trust Score Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestTrustScore:
    def test_new_agent_score_zero(self):
        engine = TrustScoreEngine()
        score = engine.compute_score("new-agent")
        assert score == 0.0

    def test_score_increases_with_success(self):
        engine = TrustScoreEngine()
        for _ in range(50):
            engine.record_success("good-agent")
        score = engine.compute_score("good-agent")
        assert score > 0.5

    def test_violations_decrease_score(self):
        engine = TrustScoreEngine()
        for _ in range(10):
            engine.record_success("mixed-agent")
        for _ in range(10):
            engine.record_violation("mixed-agent")

        score = engine.compute_score("mixed-agent")
        pure_score = engine.compute_score("nonexistent")

        # Agent with violations should have lower score than a clean agent
        # (clean agent with 0 intents returns 0, so compare to a clean agent with intents)
        engine2 = TrustScoreEngine()
        for _ in range(20):
            engine2.record_success("clean-agent")
        clean_score = engine2.compute_score("clean-agent")

        assert score < clean_score

    def test_revocation_penalty(self):
        engine = TrustScoreEngine()
        for _ in range(20):
            engine.record_success("revoked-agent")
        engine.record_revocation("revoked-agent")
        engine.record_revocation("revoked-agent")

        score = engine.compute_score("revoked-agent")

        engine2 = TrustScoreEngine()
        for _ in range(20):
            engine2.record_success("clean-agent")
        clean_score = engine2.compute_score("clean-agent")

        assert score < clean_score

    def test_threshold_check(self):
        engine = TrustScoreEngine(min_threshold=0.5)
        # New agents with no history always pass
        assert engine.meets_threshold("new-agent") is True

        # Agent with some history
        for _ in range(10):
            engine.record_success("tested-agent")
        assert engine.meets_threshold("tested-agent") is True


# ══════════════════════════════════════════════════════════════════════════════
# 6. Revocation Store Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestRevocationStore:
    def test_revoke_agent(self):
        store = RevocationStore()
        store.revoke("agent-1", reason="compromised")
        assert store.is_revoked("agent-1") is True
        assert store.is_revoked("agent-2") is False

    def test_suspend_and_expire(self):
        store = RevocationStore()
        store.suspend("agent-1", duration_seconds=0)
        # With 0 seconds, suspension is already expired
        import time
        time.sleep(0.01)
        assert store.is_revoked("agent-1") is False

    def test_reinstate(self):
        store = RevocationStore()
        store.revoke("agent-1")
        assert store.is_revoked("agent-1") is True
        store.reinstate("agent-1")
        assert store.is_revoked("agent-1") is False

    def test_nonce_replay_detection(self):
        store = RevocationStore()
        assert store.check_nonce("nonce-1") is True   # First use — OK
        assert store.check_nonce("nonce-1") is False   # Replay — BLOCKED
        assert store.check_nonce("nonce-2") is True   # Different nonce — OK


# ══════════════════════════════════════════════════════════════════════════════
# 7. Full Integration Test
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    def test_full_flow(self):
        """
        Full AIP flow:
        1. Create passport
        2. Create and sign intent
        3. Verify (should pass)
        4. Revoke agent
        5. Verify again (should fail with AGENT_REVOKED)
        """
        # 1. Create passport
        passport = AgentPassport.create(
            domain="entripse.com",
            agent_name="procurement-v1",
            allowed_actions=["read_invoice", "transfer_funds", "send_notification"],
            denied_actions=["modify_payroll"],
            monetary_limit_per_txn=50.0,
            monetary_limit_per_day=500.0,
        )

        store = RevocationStore()
        trust = TrustScoreEngine()

        # 2. Create and sign a valid intent (use Tier 1 so revocation is checked)
        env1 = create_envelope(
            passport,
            action="transfer_funds",
            target="did:web:vendor.com",
            parameters={"amount": 45.00, "currency": "USD"},
            ttl=300,
            tier=VerificationTier.TIER_1,
        )
        signed1 = sign_envelope(env1, passport.private_key)

        # 3. Verify — should pass
        result1 = verify_intent(
            signed1, passport.public_key,
            revocation_store=store,
            trust_engine=trust,
        )
        assert result1.passed is True, f"Expected pass, got errors: {result1.errors}"

        # 4. Revoke the agent
        store.revoke(passport.agent_id, reason="anomalous_behavior")

        # 5. Create a new intent and verify — should fail
        env2 = create_envelope(
            passport,
            action="read_invoice",
            ttl=300,
            tier=VerificationTier.TIER_1,
        )
        signed2 = sign_envelope(env2, passport.private_key)
        result2 = verify_intent(
            signed2, passport.public_key,
            revocation_store=store,
            trust_engine=trust,
        )
        assert result2.passed is False
        assert AIPErrorCode.AGENT_REVOKED in result2.errors

    def test_save_load_sign_verify_flow(self):
        """Test passport persistence + verification roundtrip."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and save
            passport = AgentPassport.create(
                domain="test.com",
                agent_name="persist-bot",
                allowed_actions=["read_data"],
            )
            passport.save(tmpdir)

            # Load from disk
            loaded = AgentPassport.load(tmpdir)

            # Sign with loaded passport
            env = create_envelope(loaded, action="read_data")
            signed = sign_envelope(env, loaded.private_key)

            # Verify
            store = RevocationStore()
            result = verify_intent(signed, loaded.public_key, revocation_store=store)
            assert result.passed is True

    def test_monetary_escalation_flow(self):
        """Test that high-value transactions auto-escalate to Tier 2."""
        passport = AgentPassport.create(
            domain="test.com",
            agent_name="money-bot",
            allowed_actions=["transfer_funds"],
            monetary_limit_per_txn=10000.0,
        )

        # Small amount → Tier 1 (transfer_funds is "sensitive")
        env_small = create_envelope(
            passport, action="transfer_funds",
            parameters={"amount": 50},
        )
        assert env_small.verification_tier == VerificationTier.TIER_1

        # Large amount → Tier 2
        env_large = create_envelope(
            passport, action="transfer_funds",
            parameters={"amount": 5000},
        )
        assert env_large.verification_tier == VerificationTier.TIER_2


# ══════════════════════════════════════════════════════════════════════════════
# 8. Tiered Verification Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestTieredVerification:
    def _passport(self):
        return AgentPassport.create(
            domain="test.com",
            agent_name="tier-bot",
            allowed_actions=["read_data", "transfer_funds", "send_notification"],
            monetary_limit_per_txn=100.0,
        )

    def test_tier0_skips_attestation_and_trust(self):
        """Tier 0 should only check sig + boundaries, skip attestation/revocation/trust."""
        passport = self._passport()
        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_0)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is True
        assert result.tier_used == VerificationTier.TIER_0
        assert "fast-path" in result.detail

    def test_tier1_checks_attestation_and_revocation(self):
        """Tier 1 should check attestation and revocation but skip trust/drift."""
        passport = self._passport()
        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_1)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is True
        assert result.tier_used == VerificationTier.TIER_1
        assert "standard" in result.detail

    def test_tier2_runs_full_pipeline(self):
        """Tier 2 runs all checks including trust and intent drift."""
        passport = self._passport()
        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_2)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is True
        assert result.tier_used == VerificationTier.TIER_2
        assert "Tier 2" in result.detail

    def test_tier0_still_catches_boundary_violation(self):
        """Even Tier 0 must enforce boundaries."""
        passport = self._passport()
        env = create_envelope(passport, action="delete_everything", tier=VerificationTier.TIER_0)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.ACTION_NOT_ALLOWED in result.errors

    def test_tier1_catches_revoked_agent(self):
        """Tier 1 checks revocation."""
        passport = self._passport()
        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_1)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()
        store.revoke(passport.agent_id)

        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.AGENT_REVOKED in result.errors


# ══════════════════════════════════════════════════════════════════════════════
# 9. Intent Classifier / Drift Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestIntentClassifier:
    def test_exact_match_no_drift(self):
        """Exact action match should not flag drift."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="clf-bot",
            allowed_actions=["read_data", "send_notification"],
        )
        env = create_envelope(passport, action="read_data")
        assert _check_intent_drift(env) is True

    def test_semantic_match_no_drift(self):
        """read_calendar is in the same group as read_data → no drift."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="clf-bot",
            allowed_actions=["read_data", "send_notification"],
        )
        env = create_envelope(passport, action="read_calendar")
        assert _check_intent_drift(env) is True

    def test_cross_group_drift_detected(self):
        """Financial action when only read actions allowed → drift."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="clf-bot",
            allowed_actions=["read_data", "generate_report"],
        )
        env = create_envelope(passport, action="transfer_funds")
        assert _check_intent_drift(env) is False

    def test_tier2_flags_intent_drift(self):
        """Tier 2: intent drift fires when action is in boundaries but
        semantically misaligned.  We add the action to boundaries so boundary
        check passes, but the classifier should still catch the group mismatch.

        Because _check_intent_drift returns True on exact match in allowed_actions,
        we need to bypass that.  We mutate boundaries.allowed_actions *after*
        the passport is created so the action is there for boundary check,
        but the drift classifier's exact-match won't help because the semantic
        groups still clash.

        Actually, exact match in allowed_actions means drift returns True by
        design — if the principal explicitly listed the action, it's not drift.

        So instead we test drift through the standalone classifier function
        and verify that in the full pipeline, boundary + drift form defense
        in depth: if action is NOT in allowed_actions, boundary catches it;
        if it IS, drift won't fire because it's explicitly sanctioned.
        """
        # Standalone classifier catches cross-group drift
        passport = AgentPassport.create(
            domain="test.com", agent_name="drift-bot",
            allowed_actions=["read_data", "generate_report"],
        )
        env = create_envelope(passport, action="transfer_funds", tier=VerificationTier.TIER_2)
        # transfer_funds not in allowed → classifier says drift
        assert _check_intent_drift(env) is False

        # Full pipeline: boundary check catches it first (defense in depth)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()
        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.ACTION_NOT_ALLOWED in result.errors

    def test_classify_action_groups(self):
        """Action group classification works."""
        assert _classify_action_group("transfer_funds") == "financial"
        assert _classify_action_group("read_data") == "data_read"
        assert _classify_action_group("send_notification") == "notification"
        assert _classify_action_group("delete") == "data_delete"
        assert _classify_action_group("totally_unknown_xyz") is None


# ══════════════════════════════════════════════════════════════════════════════
# 10. Attestation Verification Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAttestation:
    def test_model_hash_mismatch(self):
        """AIP-E300: model hash doesn't match registry → fail."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="attest-bot",
            allowed_actions=["read_data"],
            framework_id="did:web:langchain.com",
        )
        # Set a build hash on the passport
        passport.identity.attestation.build_hash = "sha256:actual_hash"

        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_1)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(
            signed, passport.public_key,
            revocation_store=store,
            registered_frameworks={"did:web:langchain.com"},
            known_model_hashes={"did:web:langchain.com": "sha256:expected_hash"},
        )
        assert result.passed is False
        assert AIPErrorCode.MODEL_HASH_MISMATCH in result.errors

    def test_prompt_hash_mismatch(self):
        """AIP-E301: prompt template hash changed → fail."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="prompt-bot",
            allowed_actions=["read_data"],
            system_prompt_hash="sha256:original_prompt",
        )
        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_1)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(
            signed, passport.public_key,
            revocation_store=store,
            known_prompt_hashes={passport.agent_id: "sha256:different_prompt"},
        )
        assert result.passed is False
        assert AIPErrorCode.PROMPT_HASH_MISMATCH in result.errors

    def test_correct_hashes_pass(self):
        """Correct model + prompt hashes → pass."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="good-bot",
            allowed_actions=["read_data"],
            framework_id="did:web:langchain.com",
            system_prompt_hash="sha256:prompt_abc",
        )
        passport.identity.attestation.build_hash = "sha256:model_xyz"

        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_1)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(
            signed, passport.public_key,
            revocation_store=store,
            registered_frameworks={"did:web:langchain.com"},
            known_model_hashes={"did:web:langchain.com": "sha256:model_xyz"},
            known_prompt_hashes={passport.agent_id: "sha256:prompt_abc"},
        )
        assert result.passed is True


# ══════════════════════════════════════════════════════════════════════════════
# 11. Delegation Chain Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestDelegation:
    def test_valid_delegation_chain(self):
        """Valid single-link delegation → pass on Tier 2."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="deleg-bot",
            allowed_actions=["read_data"],
        )
        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_2)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is True

    def test_expired_delegation_fails(self):
        """AIP-E403: Expired delegation link → fail on Tier 2."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="expired-deleg-bot",
            allowed_actions=["read_data"],
        )
        # Manually expire the delegation
        passport.principal.delegation_chain[0].expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        )

        env = create_envelope(passport, action="read_data", tier=VerificationTier.TIER_2)
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.DELEGATION_INVALID in result.errors


# ══════════════════════════════════════════════════════════════════════════════
# 12. Geo Restriction Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestGeoRestriction:
    def test_geo_allowed(self):
        """Request from allowed geo → pass."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="geo-bot",
            allowed_actions=["read_data"],
        )
        passport.boundaries.geo_restriction = "US,GB,IN"

        env = create_envelope(passport, action="read_data")
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(
            signed, passport.public_key,
            revocation_store=store,
            request_geo="US",
        )
        assert result.passed is True

    def test_geo_blocked(self):
        """AIP-E204: Request from restricted geo → fail."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="geo-bot",
            allowed_actions=["read_data"],
        )
        passport.boundaries.geo_restriction = "US,GB"

        env = create_envelope(passport, action="read_data")
        signed = sign_envelope(env, passport.private_key)
        store = RevocationStore()

        result = verify_intent(
            signed, passport.public_key,
            revocation_store=store,
            request_geo="CN",
        )
        assert result.passed is False
        assert AIPErrorCode.GEO_RESTRICTION in result.errors


# ══════════════════════════════════════════════════════════════════════════════
# 13. Revocation Rehydration Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestRevocationRehydration:
    def test_rehydrate_from_records(self):
        """RevocationStore can be rehydrated from DB records."""
        store = RevocationStore()
        records = [
            {
                "agent_id": "did:web:test.com:agents:bad-bot",
                "reason": "compromised",
                "revoked_by": "admin",
                "revoked_at": datetime.now(timezone.utc).isoformat(),
                "suspended_until": None,
            },
            {
                "agent_id": "did:web:test.com:agents:sus-bot",
                "reason": "anomaly",
                "revoked_by": "system",
                "revoked_at": datetime.now(timezone.utc).isoformat(),
                "suspended_until": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
            },
        ]
        loaded = store.rehydrate(records)
        assert loaded == 2
        assert store.is_revoked("did:web:test.com:agents:bad-bot") is True
        assert store.is_revoked("did:web:test.com:agents:sus-bot") is True
        assert store.is_suspended("did:web:test.com:agents:sus-bot") is True

    def test_rehydrate_skips_expired_suspensions(self):
        """Expired suspensions should not be loaded during rehydration."""
        store = RevocationStore()
        records = [
            {
                "agent_id": "did:web:test.com:agents:old-sus",
                "reason": "test",
                "revoked_by": "system",
                "revoked_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
                "suspended_until": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            },
        ]
        loaded = store.rehydrate(records)
        assert loaded == 0
        assert store.is_revoked("did:web:test.com:agents:old-sus") is False

    def test_sync_time_updates(self):
        """last_sync_time should update on revoke/suspend/reinstate/rehydrate."""
        store = RevocationStore()
        t1 = store.last_sync_time

        import time
        time.sleep(0.01)
        store.revoke("agent-x")
        assert store.last_sync_time > t1

    def test_nonce_cache_bounded(self):
        """Nonce cache should not grow unbounded."""
        store = RevocationStore()
        # Fill beyond max
        for i in range(store.MAX_NONCE_CACHE + 100):
            store.check_nonce(f"nonce-{i}")
        # Should have evicted some — cache should be bounded
        assert len(store._nonce_cache) <= store.MAX_NONCE_CACHE


# ══════════════════════════════════════════════════════════════════════════════
# 14. Schema Validation Tests (AIP-E103)
# ══════════════════════════════════════════════════════════════════════════════

class TestSchemaValidation:
    def test_empty_action_fails(self):
        """AIP-E103: Empty action field should fail schema check."""
        passport = AgentPassport.create(
            domain="test.com", agent_name="schema-bot",
            allowed_actions=["read_data"],
        )
        env = create_envelope(passport, action="read_data")
        signed = sign_envelope(env, passport.private_key)
        # Tamper with action to be empty
        signed = signed.model_copy(update={"intent": signed.intent.model_copy(update={"action": ""})})
        store = RevocationStore()

        result = verify_intent(signed, passport.public_key, revocation_store=store)
        assert result.passed is False
        assert AIPErrorCode.SCHEMA_INVALID in result.errors
