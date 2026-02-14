"""
AIP Revocation Store — In-memory revocation tracking for agents.

In production this would be backed by the Revocation Mesh (gossip protocol
+ WebSocket hot path). For V1, we use an in-memory store with:
  - Hot path: REST push with freshness tracking
  - Cold path: DB persistence for crash recovery
  - Nonce replay detection with bounded cache
"""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import NamedTuple


class RevocationRecord(NamedTuple):
    agent_id: str
    reason: str
    revoked_at: datetime
    revoked_by: str  # principal DID
    scope: str  # "global" | "scoped"
    suspended_until: datetime | None  # None = permanent revocation


class RevocationStore:
    """
    Thread-safe in-memory revocation store with freshness tracking.

    Tracks last_sync_time for revocation staleness checks (AIP-E501).
    Supports rehydration from a database on startup.
    """

    # Maximum nonce cache size to prevent unbounded memory growth
    MAX_NONCE_CACHE = 100_000

    def __init__(self) -> None:
        self._revocations: dict[str, RevocationRecord] = {}
        self._nonce_cache: set[str] = set()
        self._lock = Lock()
        self._last_sync: datetime = datetime.now(timezone.utc)

    @property
    def last_sync_time(self) -> datetime:
        """Last time revocation data was synced/updated."""
        return self._last_sync

    def touch_sync(self) -> None:
        """Mark revocation data as freshly synced."""
        self._last_sync = datetime.now(timezone.utc)

    def rehydrate(self, records: list[dict]) -> int:
        """
        Reload revocation records from persistent storage (DB).
        Call on startup to restore state after a crash/restart.

        Args:
            records: List of dicts with keys: agent_id, reason, revoked_by,
                     revoked_at (ISO str), suspended_until (ISO str or None)

        Returns:
            Number of records loaded
        """
        loaded = 0
        with self._lock:
            for r in records:
                revoked_at = r.get("revoked_at")
                if isinstance(revoked_at, str):
                    revoked_at = datetime.fromisoformat(revoked_at)
                if revoked_at and revoked_at.tzinfo is None:
                    revoked_at = revoked_at.replace(tzinfo=timezone.utc)

                suspended_until = r.get("suspended_until")
                if isinstance(suspended_until, str) and suspended_until:
                    suspended_until = datetime.fromisoformat(suspended_until)
                    if suspended_until.tzinfo is None:
                        suspended_until = suspended_until.replace(tzinfo=timezone.utc)
                    # Skip expired suspensions
                    if datetime.now(timezone.utc) > suspended_until:
                        continue
                else:
                    suspended_until = None

                record = RevocationRecord(
                    agent_id=r["agent_id"],
                    reason=r.get("reason", "unknown"),
                    revoked_at=revoked_at or datetime.now(timezone.utc),
                    revoked_by=r.get("revoked_by", "system"),
                    scope=r.get("scope", "global"),
                    suspended_until=suspended_until,
                )
                self._revocations[r["agent_id"]] = record
                loaded += 1

            self._last_sync = datetime.now(timezone.utc)
        return loaded

    def revoke(
        self,
        agent_id: str,
        reason: str = "manual_revocation",
        revoked_by: str = "unknown",
        scope: str = "global",
    ) -> RevocationRecord:
        """Revoke an agent globally."""
        record = RevocationRecord(
            agent_id=agent_id,
            reason=reason,
            revoked_at=datetime.now(timezone.utc),
            revoked_by=revoked_by,
            scope=scope,
            suspended_until=None,
        )
        with self._lock:
            self._revocations[agent_id] = record
            self._last_sync = datetime.now(timezone.utc)
        return record

    def suspend(
        self,
        agent_id: str,
        duration_seconds: int = 1800,
        reason: str = "auto_suspend",
        revoked_by: str = "circuit_breaker",
    ) -> RevocationRecord:
        """Temporarily suspend an agent."""
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        record = RevocationRecord(
            agent_id=agent_id,
            reason=reason,
            revoked_at=now,
            revoked_by=revoked_by,
            scope="global",
            suspended_until=now + timedelta(seconds=duration_seconds),
        )
        with self._lock:
            self._revocations[agent_id] = record
            self._last_sync = datetime.now(timezone.utc)
        return record

    def is_revoked(self, agent_id: str) -> bool:
        """Check if an agent is currently revoked or suspended."""
        with self._lock:
            record = self._revocations.get(agent_id)
            if record is None:
                return False

            # Check if suspension has expired
            if record.suspended_until is not None:
                if datetime.now(timezone.utc) > record.suspended_until:
                    # Suspension expired — remove it
                    del self._revocations[agent_id]
                    return False

            return True

    def is_suspended(self, agent_id: str) -> bool:
        """Check if an agent is specifically suspended (not permanently revoked)."""
        with self._lock:
            record = self._revocations.get(agent_id)
            if record is None:
                return False
            return record.suspended_until is not None

    def get_record(self, agent_id: str) -> RevocationRecord | None:
        """Get the revocation record for an agent."""
        with self._lock:
            return self._revocations.get(agent_id)

    def reinstate(self, agent_id: str) -> bool:
        """Reinstate a revoked/suspended agent. Returns True if was revoked."""
        with self._lock:
            if agent_id in self._revocations:
                del self._revocations[agent_id]
                self._last_sync = datetime.now(timezone.utc)
                return True
            return False

    # --- Replay Detection ---

    def check_nonce(self, nonce: str) -> bool:
        """
        Check if a nonce has been seen before (replay detection).
        Returns True if nonce is NEW (not a replay).
        Returns False if nonce was already used (replay attack).
        """
        with self._lock:
            if nonce in self._nonce_cache:
                return False  # Replay detected
            # Bound the cache to prevent unbounded memory growth
            if len(self._nonce_cache) >= self.MAX_NONCE_CACHE:
                # Evict oldest ~10% (set is unordered, so just discard some)
                evict_count = self.MAX_NONCE_CACHE // 10
                for _ in range(evict_count):
                    self._nonce_cache.pop()
            self._nonce_cache.add(nonce)
            return True  # New nonce, OK

    def clear_nonces(self) -> None:
        """Clear the nonce cache. Call periodically to prevent memory bloat."""
        with self._lock:
            self._nonce_cache.clear()

    @property
    def revocation_count(self) -> int:
        with self._lock:
            return len(self._revocations)
