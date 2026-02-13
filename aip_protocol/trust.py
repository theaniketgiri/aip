"""
AIP Trust Score — Compute earned trust for agents based on behavior.

Trust Score is like a credit score for agents — earned, not assigned.
An agent that always acts within its boundaries across thousands of
transactions becomes more trusted. A freshly spawned agent starts at zero.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AgentHistory:
    """Tracks an agent's behavioral history for trust computation."""
    agent_id: str
    total_intents: int = 0
    successful_intents: int = 0
    boundary_violations: int = 0
    revocation_count: int = 0
    attestation_changes: int = 0
    delegation_depth: int = 1
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TrustScoreEngine:
    """
    Compute and track trust scores for agents.

    Trust Score = weighted combination of:
      - Completion rate (successful / total)
      - Violation rate (violations / total)
      - Revocation history (penalty for past revocations)
      - Attestation stability (penalty for frequent model changes)
      - Delegation depth (deeper = less trusted)
      - Age factor (longer history = more trusted)
    """

    def __init__(self, min_threshold: float = 0.3) -> None:
        self._histories: dict[str, AgentHistory] = {}
        self.min_threshold = min_threshold

    def get_or_create(self, agent_id: str, delegation_depth: int = 1) -> AgentHistory:
        """Get or create history for an agent."""
        if agent_id not in self._histories:
            self._histories[agent_id] = AgentHistory(
                agent_id=agent_id,
                delegation_depth=delegation_depth,
            )
        return self._histories[agent_id]

    def record_success(self, agent_id: str) -> None:
        """Record a successful intent verification."""
        h = self.get_or_create(agent_id)
        h.total_intents += 1
        h.successful_intents += 1
        h.last_seen = datetime.now(timezone.utc)

    def record_violation(self, agent_id: str) -> None:
        """Record a boundary violation."""
        h = self.get_or_create(agent_id)
        h.total_intents += 1
        h.boundary_violations += 1
        h.last_seen = datetime.now(timezone.utc)

    def record_revocation(self, agent_id: str) -> None:
        """Record a revocation event."""
        h = self.get_or_create(agent_id)
        h.revocation_count += 1

    def record_attestation_change(self, agent_id: str) -> None:
        """Record a model/attestation change."""
        h = self.get_or_create(agent_id)
        h.attestation_changes += 1

    def compute_score(self, agent_id: str) -> float:
        """
        Compute the trust score for an agent. Returns 0.0 - 1.0.

        Formula:
          score = (completion_rate * 0.35)
                + (1 - violation_rate) * 0.25
                + revocation_penalty * 0.15
                + attestation_penalty * 0.10
                + depth_penalty * 0.05
                + age_bonus * 0.10
        """
        h = self.get_or_create(agent_id)

        # No history → score is 0
        if h.total_intents == 0:
            return 0.0

        # Component 1: Completion rate (0-1)
        completion_rate = h.successful_intents / h.total_intents

        # Component 2: Violation rate inverted (0-1, higher is better)
        violation_score = 1.0 - (h.boundary_violations / h.total_intents)

        # Component 3: Revocation penalty (0-1, higher is better)
        revocation_penalty = max(0.0, 1.0 - (h.revocation_count * 0.3))

        # Component 4: Attestation stability (0-1, higher is better)
        attestation_penalty = max(0.0, 1.0 - (h.attestation_changes * 0.15))

        # Component 5: Delegation depth penalty (0-1, higher is better)
        depth_penalty = max(0.0, 1.0 - (h.delegation_depth - 1) * 0.2)

        # Component 6: Age bonus (more history = more trust, capped at 1.0)
        age_bonus = min(1.0, h.total_intents / 100.0)  # Full bonus at 100 intents

        # Weighted sum
        score = (
            completion_rate * 0.35
            + violation_score * 0.25
            + revocation_penalty * 0.15
            + attestation_penalty * 0.10
            + depth_penalty * 0.05
            + age_bonus * 0.10
        )

        return round(min(1.0, max(0.0, score)), 4)

    def meets_threshold(self, agent_id: str) -> bool:
        """Check if an agent meets the minimum trust threshold."""
        h = self.get_or_create(agent_id)
        # New agents with no history always pass (benefit of the doubt)
        if h.total_intents == 0:
            return True
        return self.compute_score(agent_id) >= self.min_threshold
