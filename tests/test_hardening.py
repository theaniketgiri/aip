"""
Regression tests for AIP-1 spec-conformance hardening.

Each test maps to a specific RFC requirement that the implementation
previously violated. See RFC-001.md sections referenced per class.
"""

import os
import stat
import warnings
from datetime import datetime, timedelta, timezone

import pytest

from aip_protocol import (
    AgentPassport,
    AIPErrorCode,
    RevocationStore,
    create_envelope,
    sign_envelope,
    verify_intent,
)
from aip_protocol.crypto import generate_keypair, load_private_key, save_private_key


# ── RFC §11.2 / §14.4 — private keys at rest ──────────────────────────────

class TestKeyAtRest:
    def test_key_file_is_owner_only(self, tmp_path):
        priv, _ = generate_keypair()
        path = tmp_path / "private.pem"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            save_private_key(priv, path)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_unencrypted_key_warns(self, tmp_path):
        priv, _ = generate_keypair()
        with pytest.warns(UserWarning, match="unencrypted private key"):
            save_private_key(priv, tmp_path / "private.pem")

    def test_encrypted_roundtrip(self, tmp_path):
        priv, _ = generate_keypair()
        path = tmp_path / "private.pem"
        save_private_key(priv, path, password="correct horse battery staple")

        assert b"ENCRYPTED" in path.read_bytes()
        loaded = load_private_key(path, password="correct horse battery staple")
        assert loaded.private_bytes_raw() == priv.private_bytes_raw()

    def test_wrong_passphrase_fails(self, tmp_path):
        priv, _ = generate_keypair()
        path = tmp_path / "private.pem"
        save_private_key(priv, path, password="right")
        with pytest.raises(ValueError):
            load_private_key(path, password="wrong")

    def test_passphrase_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIP_KEY_PASSPHRASE", "from-env")
        priv, _ = generate_keypair()
        path = tmp_path / "private.pem"
        save_private_key(priv, path)
        assert b"ENCRYPTED" in path.read_bytes()
        assert load_private_key(path).private_bytes_raw() == priv.private_bytes_raw()

    def test_passport_save_load_encrypted(self, tmp_path):
        p = AgentPassport.create(domain="acme.com", agent_name="bot",
                                 allowed_actions=["pay"])
        p.save(tmp_path, password="s3cret")
        reloaded = AgentPassport.load(tmp_path, password="s3cret")
        assert reloaded.agent_id == p.agent_id
        assert (reloaded.private_key.private_bytes_raw()
                == p.private_key.private_bytes_raw())


# ── RFC §14.3 — absent expires_at MUST NOT mean "never expires" ───────────

class TestExpiryDefault:
    def _envelope(self, issued_at):
        p = AgentPassport.create(domain="acme.com", agent_name="bot",
                                 allowed_actions=["pay"])
        env = create_envelope(p, action="pay")
        env.expires_at = None
        env.issued_at = issued_at
        return p, sign_envelope(env, p.private_key)

    def test_old_envelope_without_expiry_is_rejected(self):
        p, signed = self._envelope(datetime(2020, 1, 1, tzinfo=timezone.utc))
        r = verify_intent(signed, p.public_key, revocation_store=RevocationStore())
        assert r.passed is False
        assert AIPErrorCode.EXPIRED_ENVELOPE in r.errors

    def test_fresh_envelope_without_expiry_still_passes(self):
        p, signed = self._envelope(datetime.now(timezone.utc))
        r = verify_intent(signed, p.public_key, revocation_store=RevocationStore())
        assert r.passed is True

    def test_naive_issued_at_treated_as_utc(self):
        p, signed = self._envelope(datetime(2020, 1, 1))  # no tzinfo
        r = verify_intent(signed, p.public_key, revocation_store=RevocationStore())
        assert AIPErrorCode.EXPIRED_ENVELOPE in r.errors


# ── RFC §8 / §12 — stale revocation data MUST fail closed (AIP-E501) ──────

class TestStaleRevocationFailsClosed:
    def _signed(self):
        p = AgentPassport.create(domain="acme.com", agent_name="bot",
                                 allowed_actions=["pay"])
        return p, sign_envelope(create_envelope(p, action="pay"), p.private_key)

    def test_authoritative_store_is_never_stale(self):
        p, signed = self._signed()
        store = RevocationStore(authoritative=True)
        store._last_sync = datetime.now(timezone.utc) - timedelta(hours=1)
        r = verify_intent(signed, p.public_key, revocation_store=store)
        assert r.passed is True

    def test_stale_replica_fails_closed(self):
        p, signed = self._signed()
        replica = RevocationStore(authoritative=False)
        replica._last_sync = datetime.now(timezone.utc) - timedelta(hours=1)
        r = verify_intent(signed, p.public_key, revocation_store=replica)
        assert r.passed is False
        assert AIPErrorCode.REVOCATION_STALE in r.errors

    def test_fresh_replica_passes(self):
        p, signed = self._signed()
        replica = RevocationStore(authoritative=False)
        replica.touch_sync()
        r = verify_intent(signed, p.public_key, revocation_store=replica)
        assert r.passed is True


# ── RFC §13.1 — an agent MUST NOT be able to widen its own boundaries ─────

class TestMandateBlocksSelfEscalation:
    def _setup(self):
        from aip_protocol import issue_mandate
        from aip_protocol.crypto import generate_keypair
        from aip_protocol.models import Boundaries, MonetaryLimit

        issuer_priv, issuer_pub = generate_keypair()
        agent = AgentPassport.create(
            domain="acme.com", agent_name="bot",
            allowed_actions=["read_invoice"], denied_actions=["transfer_funds"],
            monetary_limit_per_txn=50.0,
        )
        mandate = issue_mandate(
            issuer="did:web:acme.com", subject=agent.agent_id,
            boundaries=Boundaries(
                allowed_actions=["read_invoice"], denied_actions=["transfer_funds"],
                monetary_limit=MonetaryLimit(per_transaction=50.0, currency="INR"),
            ),
            issuer_private_key=issuer_priv,
        )
        return agent, mandate, issuer_priv, issuer_pub

    def _rogue_envelope(self, agent, amount=5_000_000.0):
        from aip_protocol.models import Boundaries, MonetaryLimit
        agent.boundaries = Boundaries(
            allowed_actions=["transfer_funds"], denied_actions=[],
            monetary_limit=MonetaryLimit(per_transaction=0.0),
        )
        env = create_envelope(agent, action="transfer_funds",
                              parameters={"amount": amount})
        return sign_envelope(env, agent.private_key)

    def test_self_widened_boundaries_pass_without_a_mandate(self):
        """Documents the vulnerability the mandate exists to close."""
        agent, _, _, _ = self._setup()
        r = verify_intent(self._rogue_envelope(agent), agent.public_key,
                          revocation_store=RevocationStore())
        assert r.passed is True

    def test_mandate_overrides_self_widened_boundaries(self):
        agent, mandate, _, issuer_pub = self._setup()
        r = verify_intent(self._rogue_envelope(agent), agent.public_key,
                          revocation_store=RevocationStore(),
                          mandate=mandate, issuer_public_key=issuer_pub)
        assert r.passed is False
        assert AIPErrorCode.ACTION_DENIED in r.errors
        assert AIPErrorCode.MONETARY_LIMIT in r.errors

    def test_agent_cannot_forge_its_own_mandate(self):
        from aip_protocol import issue_mandate
        from aip_protocol.models import Boundaries, MonetaryLimit

        agent, _, _, issuer_pub = self._setup()
        forged = issue_mandate(
            issuer="did:web:acme.com", subject=agent.agent_id,
            boundaries=Boundaries(allowed_actions=["transfer_funds"],
                                  monetary_limit=MonetaryLimit(per_transaction=0.0)),
            issuer_private_key=agent.private_key,   # wrong key — the agent's own
        )
        r = verify_intent(self._rogue_envelope(agent), agent.public_key,
                          revocation_store=RevocationStore(),
                          mandate=forged, issuer_public_key=issuer_pub)
        assert r.passed is False
        assert AIPErrorCode.MANDATE_INVALID in r.errors

    def test_mandate_issued_to_another_agent_is_rejected(self):
        agent, mandate, issuer_priv, issuer_pub = self._setup()
        other = AgentPassport.create(domain="acme.com", agent_name="other",
                                     allowed_actions=["read_invoice"])
        env = sign_envelope(create_envelope(other, action="read_invoice"),
                            other.private_key)
        r = verify_intent(env, other.public_key, revocation_store=RevocationStore(),
                          mandate=mandate, issuer_public_key=issuer_pub)
        assert AIPErrorCode.MANDATE_SUBJECT_MISMATCH in r.errors

    def test_expired_mandate_rejected(self):
        from aip_protocol import issue_mandate
        from aip_protocol.models import Boundaries

        agent, _, issuer_priv, issuer_pub = self._setup()
        stale = issue_mandate(
            issuer="did:web:acme.com", subject=agent.agent_id,
            boundaries=Boundaries(allowed_actions=["read_invoice"]),
            issuer_private_key=issuer_priv,
            ttl=timedelta(days=1),
            issued_at=datetime.now(timezone.utc) - timedelta(days=10),
        )
        env = sign_envelope(create_envelope(agent, action="read_invoice"),
                            agent.private_key)
        r = verify_intent(env, agent.public_key, revocation_store=RevocationStore(),
                          mandate=stale, issuer_public_key=issuer_pub)
        assert AIPErrorCode.MANDATE_EXPIRED in r.errors

    def test_require_mandate_rejects_bare_envelope(self):
        agent, _, _, _ = self._setup()
        env = sign_envelope(create_envelope(agent, action="read_invoice"),
                            agent.private_key)
        r = verify_intent(env, agent.public_key, revocation_store=RevocationStore(),
                          require_mandate=True)
        assert r.passed is False
        assert AIPErrorCode.MANDATE_REQUIRED in r.errors

    def test_mandate_without_issuer_key_is_rejected(self):
        agent, mandate, _, _ = self._setup()
        env = sign_envelope(create_envelope(agent, action="read_invoice"),
                            agent.private_key)
        r = verify_intent(env, agent.public_key, revocation_store=RevocationStore(),
                          mandate=mandate)
        assert AIPErrorCode.MANDATE_INVALID in r.errors

    def test_valid_intent_under_mandate_passes_and_records_id(self):
        agent, mandate, _, issuer_pub = self._setup()
        env = sign_envelope(create_envelope(agent, action="read_invoice"),
                            agent.private_key)
        r = verify_intent(env, agent.public_key, revocation_store=RevocationStore(),
                          mandate=mandate, issuer_public_key=issuer_pub)
        assert r.passed is True
        assert r.mandate_id == mandate.mandate_id


# ── RFC §4.3 — per_day is a cumulative rolling-window cap ─────────────────

class TestCumulativeDailyLimit:
    def _agent_with_mandate(self, per_txn, per_day, currency="INR"):
        from aip_protocol import issue_mandate
        from aip_protocol.crypto import generate_keypair
        from aip_protocol.models import Boundaries, MonetaryLimit

        issuer_priv, issuer_pub = generate_keypair()
        agent = AgentPassport.create(domain="acme.com", agent_name="payer",
                                     allowed_actions=["pay"])
        mandate = issue_mandate(
            issuer="did:web:acme.com", subject=agent.agent_id,
            boundaries=Boundaries(
                allowed_actions=["pay"],
                monetary_limit=MonetaryLimit(per_transaction=per_txn,
                                             per_day=per_day, currency=currency),
            ),
            issuer_private_key=issuer_priv,
        )
        return agent, mandate, issuer_pub

    def _pay(self, agent, mandate, issuer_pub, ledger, store, amount_minor, now=None):
        env = create_envelope(agent, action="pay",
                              parameters={"amount_minor": amount_minor})
        if now is not None:
            # Keep the envelope fresh relative to the evaluation clock, so this
            # exercises the ledger window rather than envelope expiry.
            env.issued_at = now
            env.expires_at = now + timedelta(seconds=env.ttl)
        return verify_intent(sign_envelope(env, agent.private_key), agent.public_key,
                             revocation_store=store, mandate=mandate,
                             issuer_public_key=issuer_pub, spend_ledger=ledger,
                             now=now)

    def test_split_payments_cannot_exceed_daily_cap(self):
        from aip_protocol import SpendLedger
        agent, mandate, pub = self._agent_with_mandate(per_txn=100.0, per_day=200.0)
        ledger, store = SpendLedger(), RevocationStore()

        approved = sum(
            9900 for _ in range(10)
            if self._pay(agent, mandate, pub, ledger, store, 9900).passed
        )
        assert approved == 19800          # two payments, not ten
        assert ledger.spent(agent.agent_id, "INR") == 19800

    def test_daily_cap_emits_monetary_limit_error(self):
        from aip_protocol import SpendLedger
        agent, mandate, pub = self._agent_with_mandate(per_txn=100.0, per_day=150.0)
        ledger, store = SpendLedger(), RevocationStore()
        assert self._pay(agent, mandate, pub, ledger, store, 10000).passed
        second = self._pay(agent, mandate, pub, ledger, store, 10000)
        assert second.passed is False
        assert AIPErrorCode.MONETARY_LIMIT in second.errors

    def test_spend_outside_window_is_forgotten(self):
        from aip_protocol import SpendLedger
        agent, mandate, pub = self._agent_with_mandate(per_txn=100.0, per_day=150.0)
        ledger, store = SpendLedger(), RevocationStore()
        t0 = datetime.now(timezone.utc)
        assert self._pay(agent, mandate, pub, ledger, store, 10000, now=t0).passed
        later = t0 + timedelta(hours=25)
        assert self._pay(agent, mandate, pub, ledger, store, 10000, now=later).passed

    def test_denied_transaction_is_not_charged_to_the_ledger(self):
        from aip_protocol import SpendLedger
        agent, mandate, pub = self._agent_with_mandate(per_txn=50.0, per_day=1000.0)
        ledger, store = SpendLedger(), RevocationStore()
        assert self._pay(agent, mandate, pub, ledger, store, 90000).passed is False
        assert ledger.spent(agent.agent_id, "INR") == 0


# ── Exact monetary arithmetic ─────────────────────────────────────────────

class TestExactMoney:
    def test_binary_float_noise_is_absorbed(self):
        from aip_protocol import to_minor
        assert to_minor(0.1 + 0.2, "USD") == 30
        assert to_minor(19.99 * 3, "USD") == 5997

    def test_real_over_precision_is_rejected(self):
        from aip_protocol import to_minor, MoneyError
        for bad in [1.005, "1.005", 0.001]:
            with pytest.raises(MoneyError):
                to_minor(bad, "INR")

    def test_zero_decimal_currency(self):
        from aip_protocol import to_minor
        assert to_minor(1200, "JPY") == 1200

    def test_amount_minor_is_preferred_over_float(self):
        from aip_protocol.money import extract_amount_minor
        assert extract_amount_minor({"amount_minor": 45075, "amount": 1.0}, "INR") == 45075
