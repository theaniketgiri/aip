"""
AIP Agent Passport — Create, save, load, and manage agent identities.

An Agent Passport is the persistent identity for an AI agent. It contains:
- A unique DID
- The agent's version and runtime info
- Attestation data
- The principal (owner) information
- Boundary definitions
- Cryptographic keys
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aip_protocol.crypto import (
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_to_b64,
    save_private_key,
    save_public_key,
    b64_to_public_key,
)
from aip_protocol.models import (
    AgentIdentity,
    Attestation,
    AttestationMethod,
    Boundaries,
    DelegationLink,
    MonetaryLimit,
    Principal,
    TimeWindow,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class AgentPassport:
    """
    An agent's identity + keys.

    Usage:
        # Create a new passport
        passport = AgentPassport.create(
            domain="entripse.com",
            agent_name="procurement-bot",
            principal_id="did:web:entripse.com",
            allowed_actions=["read_invoice", "transfer_funds"],
            monetary_limit_per_txn=50.0,
        )
        passport.save("./my_agent")

        # Load existing
        passport = AgentPassport.load("./my_agent")
    """

    def __init__(
        self,
        identity: AgentIdentity,
        principal: Principal,
        boundaries: Boundaries,
        private_key: Ed25519PrivateKey | None = None,
        public_key: Ed25519PublicKey | None = None,
    ):
        self.identity = identity
        self.principal = principal
        self.boundaries = boundaries
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def create(
        cls,
        domain: str = "localhost",
        agent_name: str | None = None,
        version: str = "1.0.0",
        runtime: str = "aip-sdk/0.1.0",
        principal_id: str | None = None,
        principal_type: str = "organization",
        allowed_actions: list[str] | None = None,
        denied_actions: list[str] | None = None,
        monetary_limit_per_txn: float = 0.0,
        monetary_limit_per_day: float = 0.0,
        currency: str = "USD",
        data_access: list[str] | None = None,
        framework_id: str | None = None,
        system_prompt_hash: str | None = None,
    ) -> AgentPassport:
        """Create a new agent passport with fresh keys."""
        if agent_name is None:
            agent_name = f"agent-{uuid.uuid4().hex[:8]}"

        agent_id = f"did:web:{domain}:agents:{agent_name}"
        principal_did = principal_id or f"did:web:{domain}"

        private_key, public_key = generate_keypair()

        identity = AgentIdentity(
            id=agent_id,
            version=version,
            runtime=runtime,
            attestation=Attestation(
                method=AttestationMethod.FRAMEWORK_REGISTRY if framework_id else AttestationMethod.SELF_REPORTED,
                framework_id=framework_id,
                system_prompt_hash=system_prompt_hash,
            ),
        )

        principal = Principal(
            type=principal_type,
            id=principal_did,
            delegation_chain=[
                DelegationLink(
                    **{
                        "from": principal_did,
                        "to": agent_id,
                        "scope": "default",
                        "boundary_monotonicity": True,
                        "granted_at": datetime.now(timezone.utc),
                    }
                )
            ],
        )

        boundaries = Boundaries(
            allowed_actions=allowed_actions or [],
            denied_actions=denied_actions or [],
            monetary_limit=MonetaryLimit(
                per_transaction=monetary_limit_per_txn,
                per_day=monetary_limit_per_day,
                currency=currency,
            ),
            data_access=data_access or [],
        )

        return cls(
            identity=identity,
            principal=principal,
            boundaries=boundaries,
            private_key=private_key,
            public_key=public_key,
        )

    @property
    def agent_id(self) -> str:
        return self.identity.id

    @property
    def private_key(self) -> Ed25519PrivateKey:
        if self._private_key is None:
            raise ValueError("No private key loaded — passport may be public-only")
        return self._private_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        if self._public_key is None:
            raise ValueError("No public key loaded")
        return self._public_key

    def save(self, directory: str | Path, password: str | bytes | None = None) -> None:
        """
        Save passport data + keys to a directory.

        The private key is written 0600 and encrypted when a passphrase is given
        (or AIP_KEY_PASSPHRASE is set) — see AIP-1 §11.2/§14.4.
        """
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

        # Save passport metadata
        passport_data = {
            "identity": self.identity.model_dump(mode="json"),
            "principal": self.principal.model_dump(mode="json", by_alias=True),
            "boundaries": self.boundaries.model_dump(mode="json"),
            "public_key": public_key_to_b64(self.public_key) if self._public_key else None,
        }
        (directory / "passport.json").write_text(
            json.dumps(passport_data, indent=2, default=str)
        )

        # Save keys
        if self._private_key:
            save_private_key(self._private_key, directory / "private.pem", password=password)
        if self._public_key:
            save_public_key(self._public_key, directory / "public.pem")

    @classmethod
    def load(cls, directory: str | Path, password: str | bytes | None = None) -> AgentPassport:
        """Load a passport from a directory, decrypting the private key if needed."""
        directory = Path(directory)

        passport_data = json.loads((directory / "passport.json").read_text())

        identity = AgentIdentity(**passport_data["identity"])
        principal = Principal(**passport_data["principal"])
        boundaries = Boundaries(**passport_data["boundaries"])

        private_key = None
        public_key = None

        private_key_path = directory / "private.pem"
        public_key_path = directory / "public.pem"

        if private_key_path.exists():
            private_key = load_private_key(private_key_path, password=password)
            public_key = private_key.public_key()
        elif public_key_path.exists():
            public_key = load_public_key(public_key_path)
        elif passport_data.get("public_key"):
            public_key = b64_to_public_key(passport_data["public_key"])

        return cls(
            identity=identity,
            principal=principal,
            boundaries=boundaries,
            private_key=private_key,
            public_key=public_key,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize passport to dict (without private key)."""
        return {
            "identity": self.identity.model_dump(mode="json"),
            "principal": self.principal.model_dump(mode="json", by_alias=True),
            "boundaries": self.boundaries.model_dump(mode="json"),
            "public_key": public_key_to_b64(self.public_key) if self._public_key else None,
        }

    def __repr__(self) -> str:
        return f"AgentPassport(id={self.agent_id!r})"
