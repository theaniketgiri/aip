#!/usr/bin/env python3
"""
AIP-1 Conformance Test Runner

Loads test vectors from vectors.json and validates each against
the reference Python SDK. This runner is the authoritative proof
that the SDK implements AIP-1 correctly.

For other language implementations:
  1. Load vectors.json
  2. Deserialize envelopes using your language's AIP library
  3. Run verify_intent() with the specified key material
  4. Assert the expected results

Usage:
  python conformance/run_conformance.py              # Run all tests
  python conformance/run_conformance.py -v            # Verbose mode
  python conformance/run_conformance.py -c boundary   # Run one category
  python conformance/run_conformance.py A01            # Run one test
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# Add parent to path so we can import aip_protocol
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aip_protocol.models import IntentEnvelope, VerificationTier
from aip_protocol.verification import verify_intent
from aip_protocol.revocation import RevocationStore
from aip_protocol.envelope import _get_signable_payload


# ═══════════════════════════════════════════════════════════════════════════
# Color output helpers
# ═══════════════════════════════════════════════════════════════════════════

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"


def _pass(msg: str) -> str:
    return f"  {GREEN}✓ PASS{RESET}  {msg}"


def _fail(msg: str) -> str:
    return f"  {RED}✗ FAIL{RESET}  {msg}"


def _skip(msg: str) -> str:
    return f"  {YELLOW}⊘ SKIP{RESET}  {msg}"


# ═══════════════════════════════════════════════════════════════════════════
# Key loading
# ═══════════════════════════════════════════════════════════════════════════

def load_key_material(meta: dict) -> dict:
    """Load key material from vectors metadata."""
    keys = {}
    for key_name, key_info in meta["key_material"].items():
        if key_name == "hmac_key_hex":
            keys["hmac"] = bytes.fromhex(key_info)
            continue
        pub_hex = key_info["public_key_hex"]
        pub_bytes = bytes.fromhex(pub_hex)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        keys[key_name] = public_key
    return keys


# ═══════════════════════════════════════════════════════════════════════════
# Envelope deserialization
# ═══════════════════════════════════════════════════════════════════════════

def deserialize_envelope(envelope_dict: dict) -> IntentEnvelope:
    """Deserialize a raw dict into a Pydantic IntentEnvelope."""
    return IntentEnvelope.model_validate(envelope_dict)


# ═══════════════════════════════════════════════════════════════════════════
# Single vector runner
# ═══════════════════════════════════════════════════════════════════════════

def run_vector(
    vector_id: str,
    vector: dict,
    keys: dict,
    verbose: bool = False,
) -> tuple[bool, str]:
    """
    Run a single conformance test vector.

    Returns:
        (passed: bool, detail: str)
    """
    expected = vector["expected"]
    verify_key_name = vector["verify_with"]
    category = vector.get("category", "unknown")

    # --- Set up revocation store ---
    store = RevocationStore()
    revocations = vector.get("revocations", [])
    for rev in revocations:
        if rev.get("suspended_until"):
            # Suspension — use a long duration so it doesn't expire during test
            store.suspend(
                agent_id=rev["agent_id"],
                duration_seconds=86400,
                reason=rev["reason"],
                revoked_by=rev.get("revoked_by", "system"),
            )
        else:
            store.revoke(
                agent_id=rev["agent_id"],
                reason=rev["reason"],
                revoked_by=rev.get("revoked_by", "system"),
                scope=rev.get("scope", "global"),
            )

    # --- Determine key ---
    if verify_key_name == "hmac":
        hmac_key = keys["hmac"]
        # For HMAC, we still need a public key (won't be used)
        public_key = keys["agent_1"]
    else:
        hmac_key = None
        public_key = keys[verify_key_name]

    # --- Deserialize envelope ---
    envelope = deserialize_envelope(vector["envelope"])

    # --- Handle replay test (verify_twice) ---
    if vector.get("verify_twice"):
        # First verification should pass
        first_result = verify_intent(
            envelope=envelope,
            public_key=public_key,
            revocation_store=store,
            hmac_key=hmac_key,
            request_geo=vector.get("request_geo"),
        )
        expected_first = vector.get("expected_first", {"valid": True})
        if expected_first.get("valid") and not first_result.valid:
            return False, f"First verification should have passed but got errors: {first_result.errors}"

        # Second verification — needs same nonce (store already has it)
        # Re-deserialize to get fresh envelope but nonce is same
        envelope = deserialize_envelope(vector["envelope"])
        result = verify_intent(
            envelope=envelope,
            public_key=public_key,
            revocation_store=store,
            hmac_key=hmac_key,
            request_geo=vector.get("request_geo"),
        )
    else:
        # --- Normal single verification ---
        result = verify_intent(
            envelope=envelope,
            public_key=public_key,
            revocation_store=store,
            hmac_key=hmac_key,
            request_geo=vector.get("request_geo"),
        )

    # --- Assert results ---
    failures = []

    # Check valid
    if "valid" in expected:
        if result.valid != expected["valid"]:
            failures.append(
                f"expected valid={expected['valid']}, got valid={result.valid}"
            )

    # Check signature_valid
    if "signature_valid" in expected:
        if result.signature_valid != expected["signature_valid"]:
            failures.append(
                f"expected signature_valid={expected['signature_valid']}, "
                f"got signature_valid={result.signature_valid}"
            )

    # Check within_boundaries
    if "within_boundaries" in expected:
        if result.within_boundaries != expected["within_boundaries"]:
            failures.append(
                f"expected within_boundaries={expected['within_boundaries']}, "
                f"got within_boundaries={result.within_boundaries}"
            )

    # Check error codes
    if "errors" in expected:
        expected_errors = set(expected["errors"])
        actual_errors = {e.value for e in result.errors}
        if not expected_errors.issubset(actual_errors):
            missing = expected_errors - actual_errors
            failures.append(
                f"expected errors {expected_errors}, got {actual_errors} "
                f"(missing: {missing})"
            )

    # Check tier_used
    if "tier_used" in expected:
        if result.tier_used.value != expected["tier_used"]:
            failures.append(
                f"expected tier_used={expected['tier_used']}, "
                f"got tier_used={result.tier_used.value}"
            )

    # Check canonical payload (Category H — serialization tests)
    if "canonical_payload_hex" in vector:
        actual_payload = _get_signable_payload(envelope)
        expected_hex = vector["canonical_payload_hex"]
        actual_hex = actual_payload.hex()
        if actual_hex != expected_hex:
            # Find first difference
            for i, (a, b) in enumerate(zip(actual_hex, expected_hex)):
                if a != b:
                    failures.append(
                        f"canonical payload mismatch at byte {i//2}: "
                        f"expected ...{expected_hex[max(0,i-10):i+10]}... "
                        f"got ...{actual_hex[max(0,i-10):i+10]}..."
                    )
                    break
            else:
                failures.append(
                    f"canonical payload length mismatch: "
                    f"expected {len(expected_hex)//2} bytes, got {len(actual_hex)//2}"
                )

    if failures:
        detail = "; ".join(failures)
        if verbose:
            detail += f"\n    → Actual result: valid={result.valid}, errors={[e.value for e in result.errors]}, detail={result.detail}"
        return False, detail

    return True, ""


# ═══════════════════════════════════════════════════════════════════════════
# Main runner
# ═══════════════════════════════════════════════════════════════════════════

def run_conformance(
    vectors_path: str | None = None,
    category_filter: str | None = None,
    test_filter: str | None = None,
    verbose: bool = False,
) -> int:
    """
    Run the full conformance suite.

    Returns:
        Exit code (0 = all pass, 1 = failures)
    """
    if vectors_path is None:
        vectors_path = os.path.join(os.path.dirname(__file__), "vectors.json")

    with open(vectors_path) as f:
        data = json.load(f)

    meta = data.pop("_meta")
    keys = load_key_material(meta)

    print(f"\n{BOLD}AIP-1 Conformance Test Suite{RESET}")
    print(f"{DIM}Spec: {meta['spec_version']} | Vectors: {len(data)} | Generated: {meta['generated_at']}{RESET}")
    print(f"{'─' * 70}\n")

    passed = 0
    failed = 0
    skipped = 0
    failures = []
    start = time.monotonic()

    # Group by category for display
    categories: dict[str, list[tuple[str, dict]]] = {}
    for vid, vec in data.items():
        cat = vec.get("category", "unknown")
        categories.setdefault(cat, []).append((vid, vec))

    for cat in sorted(categories.keys()):
        if category_filter and cat != category_filter:
            skipped += len(categories[cat])
            continue

        print(f"{CYAN}{BOLD}  {cat.upper()}{RESET}")

        for vid, vec in categories[cat]:
            if test_filter and test_filter.upper() not in vid.upper():
                skipped += 1
                continue

            ok, detail = run_vector(vid, vec, keys, verbose=verbose)

            if ok:
                passed += 1
                if verbose:
                    print(_pass(f"{vid}: {vec['description'][:60]}"))
                else:
                    print(_pass(vid))
            else:
                failed += 1
                print(_fail(f"{vid}: {detail}"))
                failures.append((vid, detail))

        print()

    elapsed = time.monotonic() - start

    # Summary
    print(f"{'─' * 70}")
    total = passed + failed
    if failed == 0:
        print(f"{GREEN}{BOLD}  ✓ ALL {total} VECTORS PASSED{RESET} {DIM}({elapsed*1000:.1f}ms){RESET}")
    else:
        print(f"{RED}{BOLD}  ✗ {failed}/{total} VECTORS FAILED{RESET} {DIM}({elapsed*1000:.1f}ms){RESET}")
        print(f"\n{RED}  Failures:{RESET}")
        for vid, detail in failures:
            print(f"    {vid}: {detail}")

    if skipped:
        print(f"{DIM}  ({skipped} skipped by filter){RESET}")

    print()
    return 0 if failed == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="AIP-1 Conformance Test Runner")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-c", "--category", type=str, help="Filter by category")
    parser.add_argument("test", nargs="?", help="Filter by test ID (partial match)")
    parser.add_argument("--vectors", type=str, help="Path to vectors.json")
    args = parser.parse_args()

    sys.exit(run_conformance(
        vectors_path=args.vectors,
        category_filter=args.category,
        test_filter=args.test,
        verbose=args.verbose,
    ))


if __name__ == "__main__":
    main()
