"""
AIP Cryptographic Layer — Ed25519 key management, signing, and verification.

This module handles:
- Key pair generation (Ed25519)
- Signing arbitrary data
- Verifying signatures
- Key serialization (PEM format)
"""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_data(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Sign data and return base64-encoded signature."""
    signature = private_key.sign(data)
    return base64.urlsafe_b64encode(signature).decode("utf-8")


def verify_signature(
    public_key: Ed25519PublicKey,
    data: bytes,
    signature_b64: str,
) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    try:
        signature = base64.urlsafe_b64decode(signature_b64)
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, Exception):
        return False


def save_private_key(key: Ed25519PrivateKey, path: str | Path) -> None:
    """Save a private key to PEM file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def save_public_key(key: Ed25519PublicKey, path: str | Path) -> None:
    """Save a public key to PEM file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    """Load a private key from PEM file."""
    pem = Path(path).read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519PrivateKey, got {type(key).__name__}")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    """Load a public key from PEM file."""
    pem = Path(path).read_bytes()
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519PublicKey, got {type(key).__name__}")
    return key


def public_key_to_b64(key: Ed25519PublicKey) -> str:
    """Serialize public key to base64 string (for embedding in passports)."""
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def b64_to_public_key(b64: str) -> Ed25519PublicKey:
    """Deserialize public key from base64 string."""
    raw = base64.urlsafe_b64decode(b64)
    return Ed25519PublicKey.from_public_bytes(raw)
