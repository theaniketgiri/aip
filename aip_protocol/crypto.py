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
import os
import warnings
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


def _resolve_passphrase(password: str | bytes | None) -> bytes | None:
    """Resolve a key passphrase from an argument or the AIP_KEY_PASSPHRASE env var."""
    if password is None:
        password = os.environ.get("AIP_KEY_PASSPHRASE") or None
    if password is None:
        return None
    return password.encode("utf-8") if isinstance(password, str) else password


def save_private_key(
    key: Ed25519PrivateKey,
    path: str | Path,
    password: str | bytes | None = None,
) -> None:
    """
    Save a private key to a PEM file with owner-only permissions (0600).

    AIP-1 §11.2/§14.4 require private keys to be encrypted at rest. Pass a
    passphrase, or set AIP_KEY_PASSPHRASE, to encrypt with PKCS#8 + AES.
    Unencrypted keys are still written 0600 and emit a warning.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    secret = _resolve_passphrase(password)
    if secret:
        algorithm = serialization.BestAvailableEncryption(secret)
    else:
        algorithm = serialization.NoEncryption()
        warnings.warn(
            "aip-protocol: writing an unencrypted private key. AIP-1 §14.4 requires "
            "keys to be encrypted at rest. Pass password=... or set AIP_KEY_PASSPHRASE.",
            UserWarning,
            stacklevel=2,
        )

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=algorithm,
    )
    # Create with 0600 before writing so the key is never briefly world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def save_public_key(key: Ed25519PublicKey, path: str | Path) -> None:
    """Save a public key to PEM file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_private_key(
    path: str | Path,
    password: str | bytes | None = None,
) -> Ed25519PrivateKey:
    """Load a private key from PEM file, decrypting with a passphrase if needed."""
    pem = Path(path).read_bytes()
    key = serialization.load_pem_private_key(pem, password=_resolve_passphrase(password))
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


# ── HMAC for Tier 0 fast-path ─────────────────────────────────────────────

import hashlib
import hmac as _hmac


def generate_hmac_key() -> bytes:
    """Generate a 256-bit HMAC key for Tier 0 fast-path verification."""
    import os
    return os.urandom(32)


def hmac_sign(key: bytes, data: bytes) -> str:
    """Create an HMAC-SHA256 over data, return base64-encoded."""
    digest = _hmac.new(key, data, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8")


def hmac_verify(key: bytes, data: bytes, signature_b64: str) -> bool:
    """Verify an HMAC-SHA256 signature. Returns True if valid."""
    try:
        expected = _hmac.new(key, data, hashlib.sha256).digest()
        provided = base64.urlsafe_b64decode(signature_b64)
        return _hmac.compare_digest(expected, provided)
    except Exception:
        return False
