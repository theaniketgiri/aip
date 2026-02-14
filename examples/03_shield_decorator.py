"""
AIP @shield Decorator — Protect an entire class with a decorator.

pip install aip-protocol
python examples/03_shield_decorator.py
"""

from aip_protocol import shield, AIPViolation


# ── Decorate your class — that's it ─────────────────────────────────────
@shield(
    actions=["search", "book", "cancel"],
    denied=["delete_user", "admin_override"],
    limit=1000,
    geo="US",
)
class TravelAgent:
    """An AI travel booking agent."""

    def search(self, destination: str = "", dates: str = "") -> str:
        return f"✅ Found 5 flights to {destination} on {dates}"

    def book(self, flight_id: str = "", amount: float = 0) -> str:
        return f"✅ Booked flight {flight_id} for ${amount:.2f}"

    def cancel(self, booking_id: str = "") -> str:
        return f"✅ Cancelled booking {booking_id}"


if __name__ == "__main__":
    agent = TravelAgent()

    # ✅ Search works
    print(agent.search(destination="Tokyo", dates="2026-03-01"))

    # ✅ Booking within limits
    print(agent.book(flight_id="UA123", amount=450))

    # ❌ Booking over limit
    try:
        agent.book(flight_id="EK001", amount=5000)
    except AIPViolation as e:
        print(f"❌ BLOCKED: {e}")

    print()
    print("Every method call on TravelAgent is now AIP-verified.")
    print("Cryptographic signatures. Boundary enforcement. Zero friction.")
