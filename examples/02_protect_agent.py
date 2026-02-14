"""
AIP protect_agent() — Protect any existing agent object in 1 line.

pip install aip-protocol
python examples/02_protect_agent.py
"""

from aip_protocol import protect_agent, AIPViolation


# ── Your existing agent class (no changes needed) ────────────────────────
class PaymentBot:
    """A bot that handles payments."""

    def pay(self, amount: float = 0, to: str = "") -> str:
        return f"✅ Paid ${amount:.2f} to {to}"

    def refund(self, amount: float = 0, to: str = "") -> str:
        return f"✅ Refunded ${amount:.2f} to {to}"

    def delete_account(self, user: str = "") -> str:
        return f"Deleted {user}"


# ── Protect it — 1 line ──────────────────────────────────────────────────
bot = PaymentBot()
bot = protect_agent(
    bot,
    actions=["pay", "refund"],          # Only these are allowed
    denied=["delete_account"],           # This is explicitly blocked
    limit=200,                           # $200 per transaction max
)


if __name__ == "__main__":
    # ✅ Works — $50 payment, within limits
    print(bot.pay(amount=50, to="Vendor"))

    # ✅ Works — $30 refund, within limits
    print(bot.refund(amount=30, to="Customer"))

    # ❌ Blocked — $1000 exceeds $200 limit
    try:
        bot.pay(amount=1000, to="Attacker")
    except AIPViolation as e:
        print(f"❌ BLOCKED: {e}")

    # ❌ Blocked — delete_account is in denied_actions
    try:
        bot.delete_account(user="alice")
    except AIPViolation as e:
        print(f"❌ BLOCKED: {e}")

    print()
    print("Your existing agent is now AIP-protected. Zero refactoring.")
