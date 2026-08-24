"""
AIP Spend Ledger — rolling-window monetary accounting.

RFC-001 §4.3 defines `monetary_limit.per_day` as a cumulative cap over a
24-hour rolling window. A per-transaction cap alone is trivially defeated by
splitting one payment into many: ten ₹99 transfers walk straight through a
₹200/day limit if nobody is counting.

This ledger does the counting. It is deliberately in-memory and per-verifier;
RFC §16 leaves cross-verifier aggregation open, and a distributed ledger is a
managed-mesh concern rather than a protocol one.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from threading import Lock

DEFAULT_WINDOW = timedelta(hours=24)


class SpendLedger:
    """
    Thread-safe rolling-window spend tracker, keyed by (agent_id, currency).

    Amounts are integer minor units — see aip_protocol.money.
    """

    def __init__(self, window: timedelta = DEFAULT_WINDOW) -> None:
        self._entries: dict[tuple[str, str], deque[tuple[datetime, int]]] = defaultdict(deque)
        self._window = window
        self._lock = Lock()

    def _prune(self, key: tuple[str, str], now: datetime) -> None:
        """Drop entries that have aged out of the window. Caller holds the lock."""
        cutoff = now - self._window
        entries = self._entries[key]
        while entries and entries[0][0] <= cutoff:
            entries.popleft()

    def spent(self, agent_id: str, currency: str = "USD",
              now: datetime | None = None) -> int:
        """Total minor units spent by this agent inside the rolling window."""
        now = now or datetime.now(timezone.utc)
        key = (agent_id, currency.upper())
        with self._lock:
            self._prune(key, now)
            return sum(amount for _, amount in self._entries[key])

    def would_exceed(self, agent_id: str, amount_minor: int, limit_minor: int,
                     currency: str = "USD", now: datetime | None = None) -> bool:
        """True if spending `amount_minor` now would breach `limit_minor`."""
        if limit_minor <= 0:  # 0 means "no daily cap configured"
            return False
        return self.spent(agent_id, currency, now) + amount_minor > limit_minor

    def record(self, agent_id: str, amount_minor: int, currency: str = "USD",
               now: datetime | None = None) -> None:
        """Record an authorized spend. Only call after verification succeeds."""
        if amount_minor <= 0:
            return
        now = now or datetime.now(timezone.utc)
        key = (agent_id, currency.upper())
        with self._lock:
            self._prune(key, now)
            self._entries[key].append((now, amount_minor))

    def reset(self, agent_id: str | None = None) -> None:
        """Clear the ledger, entirely or for one agent."""
        with self._lock:
            if agent_id is None:
                self._entries.clear()
            else:
                for key in [k for k in self._entries if k[0] == agent_id]:
                    del self._entries[key]
