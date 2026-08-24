"""
Razorpay client — real test-mode API when credentials are present,
a faithful simulation when they are not.

The demo must run for anyone who clones the repo, including a judge with no
Razorpay account. It therefore degrades deliberately rather than crashing:

    RAZORPAY_KEY_ID + RAZORPAY_KEY_SECRET set  ->  live test-mode API
    unset                                      ->  simulated, clearly labelled

Both paths return the same shape, so the gateway above them cannot tell the
difference — which is the point of the fallback.
"""

from __future__ import annotations

import os
import uuid
from typing import Any


class RazorpayClient:
    """Minimal client over the handful of endpoints this demo needs."""

    def __init__(self) -> None:
        self.key_id = os.environ.get("RAZORPAY_KEY_ID")
        self.key_secret = os.environ.get("RAZORPAY_KEY_SECRET")
        self.live = bool(self.key_id and self.key_secret)
        self._client = None

        if self.live:
            try:
                import razorpay  # type: ignore
                self._client = razorpay.Client(auth=(self.key_id, self.key_secret))
            except ImportError:
                self.live = False   # SDK missing — fall back rather than fail

    @property
    def mode(self) -> str:
        return "LIVE test-mode API" if self.live else "SIMULATED (no credentials)"

    # ── tools exposed to the agent ───────────────────────────────────────

    def create_payment_link(self, amount_minor: int, payee: str,
                            description: str = "", **_: Any) -> dict:
        """Create a Razorpay payment link. Amount is in paise, per their API."""
        if self.live and self._client:
            link = self._client.payment_link.create({
                "amount": int(amount_minor),
                "currency": "INR",
                "description": description or f"Agent payment to {payee}",
                "customer": {"email": payee} if "@" in payee else {},
                "notify": {"sms": False, "email": False},
            })
            return {"id": link["id"], "short_url": link.get("short_url"), "live": True}

        return {
            "id": f"plink_sim_{uuid.uuid4().hex[:12]}",
            "short_url": f"https://rzp.io/i/sim{uuid.uuid4().hex[:6]}",
            "live": False,
        }

    def create_refund(self, payment_id: str, amount_minor: int, **_: Any) -> dict:
        if self.live and self._client:
            refund = self._client.payment.refund(payment_id, {"amount": int(amount_minor)})
            return {"id": refund["id"], "live": True}
        return {"id": f"rfnd_sim_{uuid.uuid4().hex[:12]}", "live": False}

    def fetch_payments(self, count: int = 5, **_: Any) -> dict:
        if self.live and self._client:
            return {"id": None, "items": self._client.payment.all({"count": count})["items"],
                    "live": True}
        return {"id": None, "items": [{"id": f"pay_sim_{i}", "amount": 25000} for i in range(count)],
                "live": False}
