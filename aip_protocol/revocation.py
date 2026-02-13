"""
AIP Revocation Store — In-memory revocation tracking for agents.

In production this would be backed by the Revocation Mesh (gossip protocol
+ WebSocket hot path). For V1, we use an in-memory store that can be
shared across verification calls.
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
    Thread-safe in-memory revocation store.

    In production, this would be backed by:
    - Hot path: WebSocket push with ACK
    - Cold path: Append-only CRDT ledger via gossip protocol
    """

    def __init__(self) -> None:
        self._revocations: dict[str, RevocationRecord] = {}
        self._nonce_cache: set[str] = set()  # For replay detection
        self._lock = Lock()

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
