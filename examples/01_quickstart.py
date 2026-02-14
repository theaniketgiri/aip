"""
AIP Quickstart — Your first AIP-protected function in 30 seconds.

pip install aip-protocol
python examples/01_quickstart.py
"""

from aip_protocol import protect, AIPViolation

# ── Step 1: Write your function ──────────────────────────────────────────
def send_payment(amount: float, to: str) -> str:
    """Send a payment to a recipient."""
    return f"✅ Sent ${amount:.2f} to {to}"


# ── Step 2: Protect it with AIP (1 line) ─────────────────────────────────
safe_pay = protect(send_payment, actions=["send_payment"], limit=500)


# ── Step 3: Use it ───────────────────────────────────────────────────────
if __name__ == "__main__":
    # This works — $50 is under the $500 limit
    print(safe_pay(amount=50, to="Acme Corp"))

    # This is blocked — $5,000 exceeds the $500 limit
    try:
        safe_pay(amount=5000, to="Evil Corp")
    except AIPViolation as e:
        print(f"❌ {e}")

    print()
    print("That's it. Your function is now AIP-protected.")
    print("Every call is cryptographically signed and verified.")
