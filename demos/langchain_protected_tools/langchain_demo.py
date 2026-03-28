#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║             AIP × LangChain — Protected Tools Demo                         ║
║                                                                            ║
║  Four tools. Per-tool boundaries. One kill switch.                         ║
║  Every LangChain tool call is cryptographically verified by AIP.           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    pip install aip-protocol
    python langchain_demo.py

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
)
from aip_protocol.crypto import public_key_to_b64


# ─── Terminal Colors ──────────────────────────────────────────────────────────

class C:
    """ANSI color codes."""
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    RED       = "\033[91m"
    GREEN     = "\033[92m"
    YELLOW    = "\033[93m"
    BLUE      = "\033[94m"
    MAGENTA   = "\033[95m"
    CYAN      = "\033[96m"
    WHITE     = "\033[97m"
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    RESET     = "\033[0m"


def banner(text: str, color: str = C.CYAN):
    width = 72
    print()
    print(f"{color}{C.BOLD}{'═' * width}")
    print(f"  {text}")
    print(f"{'═' * width}{C.RESET}")
    print()


def section(num: int, title: str, subtitle: str = ""):
    time.sleep(0.8)
    print()
    print(f"{C.BOLD}{C.WHITE}┌──────────────────────────────────────────────────────────────┐{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}│  Scenario {num}: {title:<50}│{C.RESET}")
    if subtitle:
        print(f"{C.DIM}{C.WHITE}│  {subtitle:<60}│{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}└──────────────────────────────────────────────────────────────┘{C.RESET}")
    print()


def show_result(tool_name: str, action: str, result, amount: float = None):
    if result.valid:
        status = f"{C.GREEN}{C.BOLD}✅ ALLOWED{C.RESET}"
        detail_color = C.GREEN
    else:
        status = f"{C.RED}{C.BOLD}❌ BLOCKED{C.RESET}"
        detail_color = C.RED

    amount_str = f" (${amount:,.0f})" if amount else ""
    print(f"  {C.BOLD}Tool:{C.RESET} {C.CYAN}{tool_name}{C.RESET}  →  {C.WHITE}{action}{amount_str}{C.RESET}")
    print(f"  Status:  {status}")
    print(f"  Tier:    {C.YELLOW}{result.tier_used.value}{C.RESET}")

    if result.valid:
        print(f"  {detail_color}Detail:  {result.detail}{C.RESET}")
    else:
        error_codes = ", ".join(str(e.value) for e in result.errors)
        print(f"  {detail_color}Error:   {error_codes}{C.RESET}")
        print(f"  {detail_color}Detail:  {result.detail}{C.RESET}")
    print()


# ─── Simulated LangChain Tool Functions ───────────────────────────────────────
# These simulate what real LangChain tools would do.
# AIP verification happens BEFORE the tool executes.

def search_database(query: str) -> str:
    return f"Found 42 results for '{query}'"

def send_email(to: str, subject: str, body: str) -> str:
    return f"Email sent to {to}: {subject}"

def transfer_funds(to: str, amount: float) -> str:
    return f"Transferred ${amount:,.2f} to {to}"

def delete_records(table: str, condition: str) -> str:
    return f"Deleted records from {table} where {condition}"


# ─── AIP-Protected Tool Wrapper ──────────────────────────────────────────────

class AIPProtectedTool:
    """
    Wraps a function with AIP verification — like LangChain's AIPTool.
    Every call: create envelope → sign → verify → execute (or block).
    """

    def __init__(self, func, passport: AgentPassport, store: RevocationStore):
        self.func = func
        self.name = func.__name__
        self.passport = passport
        self.store = store

    def verify(self, parameters: dict = None) -> object:
        """Run AIP verification and return the result."""
        params = parameters or {}
        envelope = create_envelope(
            passport=self.passport,
            action=self.name,
            target="langchain-agent",
            parameters=params,
        )
        signed = sign_envelope(envelope, self.passport.private_key)
        return verify_intent(
            envelope=signed,
            public_key=self.passport.public_key,
            revocation_store=self.store,
        )

    def __call__(self, **kwargs):
        result = self.verify(kwargs)
        if not result.valid:
            error_codes = ", ".join(str(e.value) for e in result.errors)
            return f"[AIP BLOCKED] {error_codes}: {result.detail}"
        return self.func(**kwargs)


# ─── Main Demo ────────────────────────────────────────────────────────────────

def main():
    store = RevocationStore()

    banner("AIP × LangChain — Protected Tools Demo", C.CYAN)
    print(f"  {C.DIM}A LangChain agent with 4 tools, each AIP-protected with")
    print(f"  different boundaries. Every tool call is cryptographically")
    print(f"  verified before execution.{C.RESET}")
    print()

    # ── Create Agent Passport ─────────────────────────────────────────
    # Single agent with tools that have different permission levels

    agent_passport = AgentPassport.create(
        domain="fintech-startup.com",
        agent_name="assistant-agent",
        allowed_actions=["search_database", "send_email", "transfer_funds"],
        denied_actions=["delete_records"],
        monetary_limit_per_txn=500,
    )

    pub_key_short = public_key_to_b64(agent_passport.public_key)[:24] + "..."

    print(f"  {C.BOLD}{C.WHITE}Agent Identity:{C.RESET}")
    print()
    print(f"  {C.BLUE}{C.BOLD}▎ LangChain Assistant Agent{C.RESET}")
    print(f"  {C.DIM}DID:        {agent_passport.agent_id}{C.RESET}")
    print(f"  {C.DIM}Public Key: {pub_key_short}{C.RESET}")
    print(f"  {C.DIM}Limit:      $500/transaction{C.RESET}")
    print()
    print(f"  {C.BOLD}Tools & Permissions:{C.RESET}")
    print(f"  {C.GREEN}  ✓ search_database{C.RESET}  — read-only, no monetary limit")
    print(f"  {C.GREEN}  ✓ send_email{C.RESET}       — allowed, no monetary limit")
    print(f"  {C.YELLOW}  ✓ transfer_funds{C.RESET}  — allowed, capped at $500/txn")
    print(f"  {C.RED}  ✗ delete_records{C.RESET}   — explicitly DENIED")
    print()

    # Wrap tools with AIP
    search_tool = AIPProtectedTool(search_database, agent_passport, store)
    email_tool = AIPProtectedTool(send_email, agent_passport, store)
    transfer_tool = AIPProtectedTool(transfer_funds, agent_passport, store)
    delete_tool = AIPProtectedTool(delete_records, agent_passport, store)

    time.sleep(1.5)

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 1: Search database (read-only, should pass)
    # ══════════════════════════════════════════════════════════════════

    section(1, "Database Search", "Read-only tool — should pass verification")

    result = search_tool.verify({"query": "Q4 revenue reports"})
    show_result("search_database", "search_database", result)

    if result.valid:
        output = search_tool(query="Q4 revenue reports")
        print(f"  {C.GREEN}Tool output: {output}{C.RESET}")
    print()

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 2: Send email (should pass)
    # ══════════════════════════════════════════════════════════════════

    section(2, "Send Email", "Notification tool — should pass verification")

    result = email_tool.verify({"to": "cfo@fintech-startup.com", "subject": "Q4 Report", "body": "..."})
    show_result("send_email", "send_email", result)

    if result.valid:
        output = email_tool(to="cfo@fintech-startup.com", subject="Q4 Report", body="Report attached.")
        print(f"  {C.GREEN}Tool output: {output}{C.RESET}")
    print()

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 3: Transfer $200 (within limit, should pass)
    # ══════════════════════════════════════════════════════════════════

    section(3, "Transfer $200 (Within Limit)", "Under $500 cap — should pass verification")

    result = transfer_tool.verify({"to": "vendor@supplies.com", "amount": 200})
    show_result("transfer_funds", "transfer_funds", result, amount=200)

    if result.valid:
        output = transfer_tool(to="vendor@supplies.com", amount=200)
        print(f"  {C.GREEN}Tool output: {output}{C.RESET}")
    print()

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 4: Transfer $5,000 (exceeds limit)
    # ══════════════════════════════════════════════════════════════════

    section(4, "Transfer $5,000 (Over Limit)", "Exceeds $500 cap — should be BLOCKED")

    result = transfer_tool.verify({"to": "unknown@offshore.com", "amount": 5000})
    show_result("transfer_funds", "transfer_funds", result, amount=5000)

    print(f"  {C.RED}{C.BOLD}→ The agent tried to move $5,000 but its passport caps transfers at $500.{C.RESET}")
    print(f"  {C.DIM}  AIP enforces this at the cryptographic layer — the tool never executes.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 5: Delete records (denied action)
    # ══════════════════════════════════════════════════════════════════

    section(5, "Delete Records (Denied Action)", "'delete_records' is explicitly forbidden")

    result = delete_tool.verify({"table": "transactions", "condition": "date < 2025"})
    show_result("delete_records", "delete_records", result)

    print(f"  {C.RED}{C.BOLD}→ 'delete_records' is on the deny list. Not a matter of limits — it's forbidden.{C.RESET}")
    print(f"  {C.DIM}  Even if the agent had unlimited budget, this action is structurally blocked.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 6: KILL SWITCH — Revoke the agent
    # ══════════════════════════════════════════════════════════════════

    section(6, "🔴 KILL SWITCH", "Agent compromised — emergency revocation")

    time.sleep(0.5)
    print(f"  {C.BG_RED}{C.WHITE}{C.BOLD}  ⚠  AGENT REVOKED  ⚠  {C.RESET}")
    print()
    print(f"  {C.RED}Agent:   {agent_passport.agent_id}{C.RESET}")
    print(f"  {C.RED}Reason:  prompt_injection_detected{C.RESET}")
    print(f"  {C.RED}By:      did:web:fintech-startup.com (security-team){C.RESET}")
    print()

    store.revoke(
        agent_id=agent_passport.agent_id,
        reason="prompt_injection_detected",
        revoked_by="did:web:fintech-startup.com",
    )

    time.sleep(1.0)

    # Try all tools after revocation
    print(f"  {C.YELLOW}Agent tries all tools after revocation...{C.RESET}")
    print()

    r1 = search_tool.verify({"query": "passwords"})
    show_result("search_database", "search_database", r1)

    r2 = transfer_tool.verify({"to": "attacker@evil.com", "amount": 1})
    show_result("transfer_funds", "transfer_funds", r2, amount=1)

    print(f"  {C.RED}{C.BOLD}→ Every tool is dead. Even a $1 transfer. Even a read-only search.{C.RESET}")
    print(f"  {C.DIM}  The agent's cryptographic identity is burned — no action can bypass revocation.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 7: Reinstate the agent
    # ══════════════════════════════════════════════════════════════════

    section(7, "Agent Reinstated", "Threat resolved — agent restored to active duty")

    print(f"  {C.BG_GREEN}{C.WHITE}{C.BOLD}  ✓  AGENT REINSTATED  ✓  {C.RESET}")
    print()

    store.reinstate(agent_id=agent_passport.agent_id)

    time.sleep(0.8)

    r3 = search_tool.verify({"query": "market analysis"})
    show_result("search_database", "search_database", r3)

    r4 = transfer_tool.verify({"to": "vendor@supplies.com", "amount": 250})
    show_result("transfer_funds", "transfer_funds", r4, amount=250)

    print(f"  {C.GREEN}{C.BOLD}→ Agent is back online. Same passport, same keys — but revocation cleared.{C.RESET}")
    print(f"  {C.DIM}  AIP supports suspend/reinstate for incidents that are resolved.{C.RESET}")

    # ══════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════

    banner("Demo Complete", C.GREEN)
    print(f"  {C.BOLD}What AIP enforced on LangChain tools:{C.RESET}")
    print()
    print(f"  {C.GREEN}✅{C.RESET} Per-tool verification — every tool call signed + verified")
    print(f"  {C.GREEN}✅{C.RESET} Monetary limits — $500 cap blocked $5,000 transfer")
    print(f"  {C.GREEN}✅{C.RESET} Deny lists — delete_records structurally forbidden")
    print(f"  {C.RED}🔴{C.RESET} Kill switch — instant revocation, all tools dead")
    print(f"  {C.GREEN}🔄{C.RESET} Reinstatement — agent restored after incident resolved")
    print()
    print(f"  {C.BOLD}Integration with LangChain:{C.RESET}")
    print()
    print(f"  {C.DIM}  from aip_langchain import aip_tool")
    print(f"")
    print(f"  {C.DIM}  @aip_tool(limit=500)")
    print(f"  {C.DIM}  def transfer_funds(amount: float, to: str) -> str:")
    print(f"  {C.DIM}      return f\"Sent ${{amount}} to {{to}}\"{C.RESET}")
    print()
    print(f"  {C.DIM}All verification: local, sub-millisecond, zero network calls.")
    print(f"  Learn more: https://github.com/theaniketgiri/aip{C.RESET}")
    print()


if __name__ == "__main__":
    main()
