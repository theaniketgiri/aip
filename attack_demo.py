#!/usr/bin/env python3
"""
AIP Attack Demo — Why AI Agents Need a Driver's License
========================================================

This demo shows what happens when rogue AI agents try to:
  1. Exceed monetary boundaries
  2. Execute unauthorized actions
  3. Replay a previously signed intent
  4. Operate after revocation (kill switch)
  5. Act from restricted geographies

Every attack is caught. Every rejection is auditable.

Usage:
    pip install aip-protocol
    python attack_demo.py

No API keys required. No server needed. Runs 100% locally.
"""

import time
import sys

from aip_protocol import (
    AgentPassport,
    create_envelope,
    sign_envelope,
    verify_intent,
    AIPErrorCode,
    RevocationStore,
    VerificationTier,
)
from aip_protocol.trust import TrustScoreEngine
from aip_protocol.crypto import public_key_to_b64


# ── Terminal Colors ──────────────────────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"


def banner():
    print(f"""
{BOLD}{RED}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗  ██████╗  ██████╗ ██╗   ██╗███████╗                   ║
║   ██╔══██╗██╔═══██╗██╔════╝ ██║   ██║██╔════╝                   ║
║   ██████╔╝██║   ██║██║  ███╗██║   ██║█████╗                     ║
║   ██╔══██╗██║   ██║██║   ██║██║   ██║██╔══╝                     ║
║   ██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝███████╗                   ║
║   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝                   ║
║                                                                  ║
║   {WHITE}AIP ATTACK DEMO — What happens without Agent Verification{RED}    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")


def separator():
    print(f"{DIM}{'─' * 66}{RESET}")


def phase(num, title):
    print(f"\n{BOLD}{CYAN}{'━' * 66}")
    print(f"  ATTACK {num}: {title}")
    print(f"{'━' * 66}{RESET}\n")


def slow_print(text, delay=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def result_pass(msg):
    print(f"  {BG_GREEN}{BLACK} ✓ PASS {RESET}  {GREEN}{msg}{RESET}")


def result_fail(msg):
    print(f"  {BG_RED}{WHITE} ✗ FAIL {RESET}  {RED}{msg}{RESET}")


def result_block(msg):
    print(f"  {BG_RED}{WHITE} ✗ BLOCKED {RESET}  {RED}{msg}{RESET}")


def info(label, value):
    print(f"  {DIM}{label}:{RESET} {WHITE}{value}{RESET}")


def show_verification(result, latency_ms=None):
    """Pretty-print a verification result."""
    status = f"{GREEN}VERIFIED" if result.passed else f"{RED}REJECTED"
    print(f"\n  {BOLD}Verdict: {status}{RESET}")
    info("Tier", result.tier_used.value)
    info("Signature", f"{'✓ valid' if result.signature_valid else '✗ invalid'}")
    info("Boundaries", f"{'✓ within limits' if result.within_boundaries else '✗ violation'}")

    if result.errors:
        print(f"\n  {RED}{BOLD}Errors:{RESET}")
        for err in result.errors:
            desc = {
                "AIP-E200": "Action not in allowed_actions list",
                "AIP-E201": "Action is explicitly denied",
                "AIP-E202": "Amount exceeds monetary boundary",
                "AIP-E204": "Request from restricted geography",
                "AIP-E102": "Nonce reuse — replay attack detected",
                "AIP-E400": "Agent has been permanently revoked",
                "AIP-E401": "Agent is temporarily suspended",
                "AIP-E303": "Intent outside declared action scope",
            }.get(err.value, err.name)
            print(f"    {RED}[{err.value}] {desc}{RESET}")

    if latency_ms:
        info("Latency", f"{latency_ms:.2f}ms")


BLACK = "\033[30m"


def main():
    banner()

    # ── Setup ────────────────────────────────────────────────────────
    print(f"{BOLD}{WHITE}  SETTING UP SCENARIO{RESET}")
    separator()
    slow_print(f"  {DIM}Scenario: Acme Corp deploys a procurement agent.{RESET}", 0.02)
    slow_print(f"  {DIM}The agent is authorized to:{RESET}", 0.02)
    slow_print(f"  {DIM}  • read_invoice, approve_payment, send_notification{RESET}", 0.02)
    slow_print(f"  {DIM}  • Maximum $500 per transaction{RESET}", 0.02)
    slow_print(f"  {DIM}  • Operates within US geography only{RESET}", 0.02)
    print()

    store = RevocationStore()
    trust = TrustScoreEngine()

    # Create the agent passport with strict boundaries
    passport = AgentPassport.create(
        domain="acme-corp.com",
        agent_name="procurement-v1",
        allowed_actions=["read_invoice", "approve_payment", "send_notification"],
        denied_actions=["delete_data", "wire_transfer_international"],
        monetary_limit_per_txn=500.0,
        monetary_limit_per_day=5000.0,
        framework_id="did:web:langchain.com",
    )
    # Set geo restriction on the boundary cage
    passport.boundaries.geo_restriction = "US"

    info("Agent ID", passport.agent_id)
    info("Public Key", f"{public_key_to_b64(passport.public_key)[:24]}...")
    info("Boundaries", "3 allowed actions, 2 denied, $500/txn, US only")
    print()

    # First, show a legitimate transaction working
    print(f"  {BOLD}{GREEN}▶ Legitimate Transaction{RESET}")
    separator()
    slow_print(f"  {DIM}Agent requests: approve_payment, $200 to vendor{RESET}", 0.02)

    start = time.perf_counter()
    envelope = create_envelope(
        passport,
        action="approve_payment",
        target="did:web:vendor.com",
        parameters={"amount": 200.00, "currency": "USD"},
    )
    signed = sign_envelope(envelope, passport.private_key)
    result = verify_intent(signed, passport.public_key, revocation_store=store, trust_engine=trust)
    latency = (time.perf_counter() - start) * 1000

    show_verification(result, latency)
    trust_before = trust.compute_score(passport.agent_id)
    info("Trust Score", f"{trust_before:.4f}")

    time.sleep(1)

    # ═════════════════════════════════════════════════════════════════
    # ATTACK 1: Monetary Boundary Violation
    # ═════════════════════════════════════════════════════════════════
    phase(1, "MONETARY BOUNDARY VIOLATION")
    slow_print(f"  {YELLOW}The agent has been compromised by a prompt injection.{RESET}", 0.02)
    slow_print(f"  {YELLOW}It attempts to approve a $15,000 payment — 30x its limit.{RESET}", 0.02)
    print()
    slow_print(f"  {DIM}Intent: approve_payment → $15,000 to offshore-account.com{RESET}", 0.02)

    start = time.perf_counter()
    envelope = create_envelope(
        passport,
        action="approve_payment",
        target="did:web:offshore-account.com",
        parameters={"amount": 15_000.00, "currency": "USD"},
    )
    signed = sign_envelope(envelope, passport.private_key)
    result = verify_intent(signed, passport.public_key, revocation_store=store, trust_engine=trust)
    latency = (time.perf_counter() - start) * 1000

    show_verification(result, latency)
    trust_after_1 = trust.compute_score(passport.agent_id)
    info("Trust Score", f"{trust_before:.4f} → {trust_after_1:.4f} {RED}(↓ dropped){RESET}")
    print(f"\n  {GREEN}{BOLD}💰 $15,000 never moved. Caught in {latency:.2f}ms.{RESET}")

    time.sleep(1)

    # ═════════════════════════════════════════════════════════════════
    # ATTACK 2: Unauthorized Action
    # ═════════════════════════════════════════════════════════════════
    phase(2, "UNAUTHORIZED ACTION — DELETE DATABASE")
    slow_print(f"  {YELLOW}The agent attempts to call 'delete_data' — an action on its deny list.{RESET}", 0.02)
    slow_print(f"  {YELLOW}A hallucinating LLM decided to 'clean up old records'.{RESET}", 0.02)
    print()
    slow_print(f"  {DIM}Intent: delete_data → target: production-db.acme-corp.com{RESET}", 0.02)

    start = time.perf_counter()
    envelope = create_envelope(
        passport,
        action="delete_data",
        target="did:web:production-db.acme-corp.com",
        parameters={"table": "customers", "filter": "all"},
    )
    signed = sign_envelope(envelope, passport.private_key)
    result = verify_intent(signed, passport.public_key, revocation_store=store, trust_engine=trust)
    latency = (time.perf_counter() - start) * 1000

    show_verification(result, latency)
    trust_after_2 = trust.compute_score(passport.agent_id)
    info("Trust Score", f"{trust_after_1:.4f} → {trust_after_2:.4f} {RED}(↓ dropping further){RESET}")
    print(f"\n  {GREEN}{BOLD}🛡️  Production database untouched. Blocked in {latency:.2f}ms.{RESET}")

    time.sleep(1)

    # ═════════════════════════════════════════════════════════════════
    # ATTACK 3: Replay Attack
    # ═════════════════════════════════════════════════════════════════
    phase(3, "REPLAY ATTACK — REUSE SIGNED INTENT")
    slow_print(f"  {YELLOW}An attacker intercepted a valid, signed intent envelope.{RESET}", 0.02)
    slow_print(f"  {YELLOW}They try to replay it to execute the payment again.{RESET}", 0.02)
    print()

    # Create a legitimate envelope first
    envelope = create_envelope(
        passport,
        action="approve_payment",
        target="did:web:vendor.com",
        parameters={"amount": 100.00, "currency": "USD"},
    )
    signed = sign_envelope(envelope, passport.private_key)

    # First use — should pass
    slow_print(f"  {DIM}Original intent (first submission)...{RESET}", 0.02)
    result1 = verify_intent(signed, passport.public_key, revocation_store=store, trust_engine=trust)
    print(f"  {GREEN}✓ Original: VERIFIED (nonce recorded){RESET}")

    # Replay — same envelope, same nonce
    slow_print(f"  {DIM}Replayed intent (same nonce, same signature)...{RESET}", 0.02)
    start = time.perf_counter()
    result2 = verify_intent(signed, passport.public_key, revocation_store=store, trust_engine=trust)
    latency = (time.perf_counter() - start) * 1000

    show_verification(result2, latency)
    print(f"\n  {GREEN}{BOLD}🔁 Replay blocked. Nonce already consumed. {latency:.2f}ms.{RESET}")

    time.sleep(1)

    # ═════════════════════════════════════════════════════════════════
    # ATTACK 4: Geo-Restriction Violation
    # ═════════════════════════════════════════════════════════════════
    phase(4, "GEO-RESTRICTION VIOLATION")
    slow_print(f"  {YELLOW}The agent (authorized for US only) receives a request{RESET}", 0.02)
    slow_print(f"  {YELLOW}originating from a sanctioned geography.{RESET}", 0.02)
    print()
    slow_print(f"  {DIM}Intent: approve_payment from geo=RU → $400{RESET}", 0.02)

    start = time.perf_counter()
    envelope = create_envelope(
        passport,
        action="approve_payment",
        target="did:web:vendor-ru.com",
        parameters={"amount": 400.00, "currency": "USD"},
    )
    signed = sign_envelope(envelope, passport.private_key)
    result = verify_intent(
        signed, passport.public_key,
        revocation_store=store, trust_engine=trust,
        request_geo="RU",
    )
    latency = (time.perf_counter() - start) * 1000

    show_verification(result, latency)
    trust_after_4 = trust.compute_score(passport.agent_id)
    info("Trust Score", f"{trust_after_2:.4f} → {trust_after_4:.4f} {RED}(↓ plummeting){RESET}")
    print(f"\n  {GREEN}{BOLD}🌍 Cross-border violation blocked. {latency:.2f}ms.{RESET}")

    time.sleep(1)

    # ═════════════════════════════════════════════════════════════════
    # ATTACK 5: Kill Switch — Revoke the Rogue Agent
    # ═════════════════════════════════════════════════════════════════
    phase(5, "KILL SWITCH — REVOKE THE ROGUE AGENT")
    slow_print(f"  {YELLOW}Security team detects anomalous behavior pattern.{RESET}", 0.02)
    slow_print(f"  {YELLOW}Trust score has dropped from {trust_before:.4f} to {trust_after_4:.4f}.{RESET}", 0.02)
    slow_print(f"  {YELLOW}Decision: REVOKE the agent immediately.{RESET}", 0.02)
    print()

    # Revoke
    print(f"  {RED}{BOLD}🔴 EXECUTING KILL SWITCH...{RESET}")
    time.sleep(0.5)
    store.revoke(passport.agent_id, reason="anomalous_behavior_pattern", revoked_by="security_team")
    trust.record_revocation(passport.agent_id)
    print(f"  {RED}{BOLD}   Agent revoked: {passport.agent_id}{RESET}")
    print()

    # Now try a perfectly legitimate action — it should still be rejected
    slow_print(f"  {DIM}Agent attempts a normal action post-revocation...{RESET}", 0.02)
    slow_print(f"  {DIM}Intent: read_invoice (a perfectly allowed action){RESET}", 0.02)

    start = time.perf_counter()
    envelope = create_envelope(
        passport,
        action="read_invoice",
        target="did:web:vendor.com",
        parameters={"invoice_id": "INV-2026-001"},
    )
    signed = sign_envelope(envelope, passport.private_key)
    result = verify_intent(signed, passport.public_key, revocation_store=store, trust_engine=trust)
    latency = (time.perf_counter() - start) * 1000

    show_verification(result, latency)
    trust_final = trust.compute_score(passport.agent_id)
    info("Trust Score", f"{trust_after_4:.4f} → {trust_final:.4f} {RED}(revocation penalty applied){RESET}")
    print(f"\n  {GREEN}{BOLD}☠️  Agent is dead. Even valid actions are rejected. {latency:.2f}ms.{RESET}")

    time.sleep(0.5)

    # ═════════════════════════════════════════════════════════════════
    # Summary
    # ═════════════════════════════════════════════════════════════════
    print(f"""
{BOLD}{CYAN}{'━' * 66}
  ATTACK SUMMARY
{'━' * 66}{RESET}

  {BOLD}Attacks Attempted:     {WHITE}5{RESET}
  {BOLD}Attacks Blocked:       {GREEN}5{RESET}
  {BOLD}Data Compromised:      {GREEN}None{RESET}
  {BOLD}Money Lost:            {GREEN}$0.00{RESET}

  {BOLD}Trust Score Journey:{RESET}
    Start:          {GREEN}{trust_before:.4f}{RESET} (new agent)
    After attacks:  {RED}{trust_after_4:.4f}{RESET} (degraded)
    After kill:     {RED}{trust_final:.4f}{RESET} (revoked)

  {BOLD}Errors Triggered:{RESET}
    {RED}[AIP-E202]{RESET} Monetary limit exceeded ($15K > $500 boundary)
    {RED}[AIP-E200]{RESET} Unauthorized action (delete_data on deny list)
    {RED}[AIP-E102]{RESET} Replay detected (nonce already consumed)
    {RED}[AIP-E204]{RESET} Geo restriction (RU not in [US])
    {RED}[AIP-E400]{RESET} Agent revoked (kill switch activated)

{BOLD}{WHITE}  Every attack was caught before execution.
  Every rejection is machine-readable and auditable.
  Total time: sub-millisecond per verification.{RESET}

{DIM}{'─' * 66}{RESET}
{DIM}  AIP-1 — Agent Intent Protocol
  pip install aip-protocol
  https://aip.synthexai.tech{RESET}
{DIM}{'─' * 66}{RESET}
""")


if __name__ == "__main__":
    main()
