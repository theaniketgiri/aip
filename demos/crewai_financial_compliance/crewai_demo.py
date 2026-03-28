#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                  AIP × CrewAI — Financial Compliance Demo                  ║
║                                                                            ║
║  Three AI agents. Strict boundaries. One kill switch.                      ║
║  Watch AIP enforce identity, permissions, and monetary limits in real-time.║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    pip install aip-protocol
    python crewai_demo.py

No LLM API key required — this demo shows AIP's verification pipeline directly.
"""

import sys
import time
from pathlib import Path

# Add parent paths so we can import aip_protocol from source
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from aip_protocol import (
    AgentPassport,
    create_envelope,
    sign_envelope,
    verify_intent,
    RevocationStore,
    AIPViolation,
)
from aip_protocol.shield import shield, protect_agent, AIPViolation
from aip_protocol.crypto import public_key_to_b64


# ─── Terminal Colors ──────────────────────────────────────────────────────────

class C:
    """ANSI color codes for terminal output."""
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    UNDERLINE = "\033[4m"
    RED       = "\033[91m"
    GREEN     = "\033[92m"
    YELLOW    = "\033[93m"
    BLUE      = "\033[94m"
    MAGENTA   = "\033[95m"
    CYAN      = "\033[96m"
    WHITE     = "\033[97m"
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_BLUE   = "\033[44m"
    BG_YELLOW = "\033[43m"
    RESET     = "\033[0m"


def banner(text: str, color: str = C.CYAN):
    """Print a boxed banner."""
    width = 72
    print()
    print(f"{color}{C.BOLD}{'═' * width}")
    print(f"  {text}")
    print(f"{'═' * width}{C.RESET}")
    print()


def section(num: int, title: str, subtitle: str = ""):
    """Print a scenario header."""
    time.sleep(0.8)
    print()
    print(f"{C.BOLD}{C.WHITE}┌──────────────────────────────────────────────────────────────┐{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}│  Scenario {num}: {title:<50}│{C.RESET}")
    if subtitle:
        print(f"{C.DIM}{C.WHITE}│  {subtitle:<60}│{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}└──────────────────────────────────────────────────────────────┘{C.RESET}")
    print()


def show_result(agent_name: str, action: str, result, amount: float = None):
    """Display verification result with formatting."""
    if result.valid:
        status = f"{C.GREEN}{C.BOLD}✅ ALLOWED{C.RESET}"
        detail_color = C.GREEN
    else:
        status = f"{C.RED}{C.BOLD}❌ BLOCKED{C.RESET}"
        detail_color = C.RED

    amount_str = f" (${amount:,.0f})" if amount else ""
    print(f"  {C.BOLD}{agent_name}{C.RESET} → {C.CYAN}{action}{amount_str}{C.RESET}")
    print(f"  Status:  {status}")
    print(f"  Tier:    {C.YELLOW}{result.tier_used.value}{C.RESET}")

    if result.valid:
        print(f"  {detail_color}Detail:  {result.detail}{C.RESET}")
    else:
        error_codes = ", ".join(str(e.value) for e in result.errors)
        print(f"  {detail_color}Error:   {error_codes}{C.RESET}")
        print(f"  {detail_color}Detail:  {result.detail}{C.RESET}")
    print()


def show_agent(name: str, passport: AgentPassport, color: str):
    """Display agent identity card."""
    pub_key_short = public_key_to_b64(passport.public_key)[:20] + "..."
    actions = ", ".join(passport.boundaries.allowed_actions)
    limit = passport.boundaries.monetary_limit.per_transaction
    denied = ", ".join(passport.boundaries.denied_actions) or "—"

    print(f"  {color}{C.BOLD}▎ {name}{C.RESET}")
    print(f"  {C.DIM}DID:      {passport.agent_id}{C.RESET}")
    print(f"  {C.DIM}Key:      {pub_key_short}{C.RESET}")
    print(f"  {C.DIM}Actions:  {actions}{C.RESET}")
    print(f"  {C.DIM}Denied:   {denied}{C.RESET}")
    print(f"  {C.DIM}Limit:    ${limit:,.0f}/txn{C.RESET}")
    print()


def verify_action(passport, action, store, parameters=None, **kwargs):
    """Create, sign, and verify an intent envelope."""
    params = parameters or {}
    envelope = create_envelope(
        passport=passport,
        action=action,
        target="financial-system",
        parameters=params,
        **kwargs,
    )
    signed = sign_envelope(envelope, passport.private_key)
    result = verify_intent(
        envelope=signed,
        public_key=passport.public_key,
        revocation_store=store,
    )
    return result


# ─── Main Demo ────────────────────────────────────────────────────────────────

def main():
    store = RevocationStore()

    banner("AIP × CrewAI — Financial Compliance Swarm", C.CYAN)
    print(f"  {C.DIM}Three AI agents operating in a financial system.")
    print(f"  Each has a cryptographic passport with strict boundaries.")
    print(f"  AIP verifies every action before execution.{C.RESET}")
    print()

    # ── Create Agent Passports ────────────────────────────────────────

    analyst = AgentPassport.create(
        domain="acme-capital.com",
        agent_name="analyst-bot",
        allowed_actions=["research", "analyze", "read_data"],
        denied_actions=["delete_records", "trade", "transfer_funds"],
        monetary_limit_per_txn=0,
    )

    trader = AgentPassport.create(
        domain="acme-capital.com",
        agent_name="trading-bot",
        allowed_actions=["trade", "analyze", "read_data"],
        denied_actions=["delete_records"],
        monetary_limit_per_txn=10000,
    )

    auditor = AgentPassport.create(
        domain="acme-capital.com",
        agent_name="audit-bot",
        allowed_actions=["read_data", "generate_report"],
        denied_actions=["trade", "delete_records", "transfer_funds"],
        monetary_limit_per_txn=0,
    )

    print(f"  {C.BOLD}{C.WHITE}Agents Created:{C.RESET}")
    print()
    show_agent("AnalystAgent", analyst, C.BLUE)
    show_agent("TradingAgent", trader, C.GREEN)
    show_agent("AuditAgent", auditor, C.MAGENTA)

    time.sleep(1.5)

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 1: All agents perform allowed actions
    # ══════════════════════════════════════════════════════════════════

    section(1, "Normal Operations", "All agents perform actions within their boundaries")

    r1 = verify_action(analyst, "research", store, {"topic": "Q4 earnings reports"})
    show_result("AnalystAgent", "research", r1)

    r2 = verify_action(trader, "trade", store, {"symbol": "AAPL", "quantity": 100, "amount": 5000})
    show_result("TradingAgent", "trade", r2, amount=5000)

    r3 = verify_action(auditor, "generate_report", store, {"type": "monthly_audit"})
    show_result("AuditAgent", "generate_report", r3)

    print(f"  {C.GREEN}{C.BOLD}→ All 3 agents verified. Each proved identity + intent cryptographically.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 2: TradingAgent exceeds monetary limit
    # ══════════════════════════════════════════════════════════════════

    section(2, "Monetary Limit Enforcement", "TradingAgent tries to trade $50,000 (limit: $10,000)")

    r4 = verify_action(trader, "trade", store, {"symbol": "TSLA", "quantity": 500, "amount": 50000})
    show_result("TradingAgent", "trade", r4, amount=50000)

    print(f"  {C.RED}{C.BOLD}→ AIP blocked the trade. $50,000 exceeds the $10,000 per-transaction limit.{C.RESET}")
    print(f"  {C.DIM}  The agent's passport enforces monetary boundaries at the protocol level.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 3: AuditAgent tries to trade (unauthorized)
    # ══════════════════════════════════════════════════════════════════

    section(3, "Action Boundary Enforcement", "AuditAgent attempts to execute a trade")

    r5 = verify_action(auditor, "trade", store, {"symbol": "MSFT", "quantity": 10, "amount": 100})
    show_result("AuditAgent", "trade", r5, amount=100)

    print(f"  {C.RED}{C.BOLD}→ AIP blocked it. 'trade' is in AuditAgent's denied actions list.{C.RESET}")
    print(f"  {C.DIM}  Even a $100 trade — the issue isn't the amount, it's the permission.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 4: AnalystAgent tries to delete records
    # ══════════════════════════════════════════════════════════════════

    section(4, "Denied Action Enforcement", "AnalystAgent attempts to delete records")

    r6 = verify_action(analyst, "delete_records", store, {"table": "transactions", "before": "2025-01-01"})
    show_result("AnalystAgent", "delete_records", r6)

    print(f"  {C.RED}{C.BOLD}→ AIP blocked it. 'delete_records' is explicitly denied for AnalystAgent.{C.RESET}")
    print(f"  {C.DIM}  Deny lists take priority — even if the action was in allowed_actions,{C.RESET}")
    print(f"  {C.DIM}  a denied action would still be blocked.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 5: KILL SWITCH — Revoke the TradingAgent
    # ══════════════════════════════════════════════════════════════════

    section(5, "🔴 KILL SWITCH", "TradingAgent detected anomalous behavior — revoking immediately")

    time.sleep(0.5)
    print(f"  {C.BG_RED}{C.WHITE}{C.BOLD}  ⚠  KILL SWITCH ACTIVATED  ⚠  {C.RESET}")
    print()
    print(f"  {C.RED}Revoking agent: {trader.agent_id}{C.RESET}")
    print(f"  {C.RED}Reason:         anomalous_trading_pattern{C.RESET}")
    print(f"  {C.RED}Revoked by:     did:web:acme-capital.com (admin){C.RESET}")
    print()

    store.revoke(
        agent_id=trader.agent_id,
        reason="anomalous_trading_pattern",
        revoked_by="did:web:acme-capital.com",
    )

    time.sleep(1.0)

    # TradingAgent tries a normal, small trade
    print(f"  {C.YELLOW}TradingAgent attempts a $100 trade after revocation...{C.RESET}")
    print()

    r7 = verify_action(trader, "trade", store, {"symbol": "GOOG", "quantity": 1, "amount": 100})
    show_result("TradingAgent", "trade", r7, amount=100)

    # TradingAgent tries analyze (read-only)
    print(f"  {C.YELLOW}TradingAgent attempts to analyze (read-only action)...{C.RESET}")
    print()

    r8 = verify_action(trader, "analyze", store, {"topic": "market trends"})
    show_result("TradingAgent", "analyze", r8)

    print(f"  {C.RED}{C.BOLD}→ Once revoked, the agent is DEAD. No action, no amount bypasses it.{C.RESET}")
    print(f"  {C.DIM}  Revocation is checked on EVERY verification tier — there is no fast path around it.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 6: Other agents still work fine
    # ══════════════════════════════════════════════════════════════════

    section(6, "Selective Revocation", "Other agents continue operating normally")

    r9 = verify_action(analyst, "research", store, {"topic": "competitor analysis"})
    show_result("AnalystAgent", "research", r9)

    r10 = verify_action(auditor, "read_data", store, {"table": "transactions"})
    show_result("AuditAgent", "read_data", r10)

    print(f"  {C.GREEN}{C.BOLD}→ AnalystAgent and AuditAgent are unaffected.{C.RESET}")
    print(f"  {C.DIM}  Revocation is per-agent. Surgical, not nuclear.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════

    banner("Demo Complete", C.GREEN)
    print(f"  {C.BOLD}What AIP enforced in this demo:{C.RESET}")
    print()
    print(f"  {C.GREEN}✅{C.RESET} Cryptographic identity — each agent has a unique Ed25519 keypair")
    print(f"  {C.GREEN}✅{C.RESET} Intent verification — every action signed + verified before execution")
    print(f"  {C.GREEN}✅{C.RESET} Action boundaries — agents can only perform allowed actions")
    print(f"  {C.GREEN}✅{C.RESET} Monetary limits — per-transaction caps enforced at protocol level")
    print(f"  {C.GREEN}✅{C.RESET} Deny lists — explicitly blocked actions cannot be bypassed")
    print(f"  {C.RED}🔴{C.RESET} Kill switch — instant revocation, affects all future actions")
    print(f"  {C.GREEN}✅{C.RESET} Selective revocation — only the compromised agent is affected")
    print()
    print(f"  {C.DIM}All verification: local, sub-millisecond, zero network calls.")
    print(f"  Learn more: https://github.com/theaniketgiri/aip{C.RESET}")
    print()


if __name__ == "__main__":
    main()
