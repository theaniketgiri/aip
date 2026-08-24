"""
AIP Gateway — action-level authorization in front of Razorpay tool calls.

WHERE THIS SITS

    LLM agent  ──►  AIP Gateway  ──►  Razorpay MCP / API
                        │
                        └──►  audit log (every allow AND deny)

UPI Reserve Pay already caps how much an agent may spend against a merchant
(NPCI Single Block Multi Debit: a reserved amount, up to 90 days, revocable).
That is a RAILS-level cap and it is the right primitive for the amount.

It does not govern WHAT the agent does inside that reserve. A prompt-injected
agent holding a valid ₹10,000 block can still pay the wrong payee, call the
wrong tool, or act outside the scope its operator intended — every one of
those is a legal debit against the block.

This gateway adds the action-level layer: which tools, which payees, which
amounts, with a machine-readable reason for every refusal and an audit row
for both outcomes.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable

from aip_protocol import (
    AgentPassport,
    Mandate,
    RevocationStore,
    SpendLedger,
    create_envelope,
    sign_envelope,
    verify_intent,
)
from aip_protocol.money import extract_amount_minor, format_minor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass
class AuditRow:
    """One authorization decision. Emitted for allows and denies alike."""
    ts: str
    agent_id: str
    tool: str
    parameters: dict[str, Any]
    decision: str                      # "allow" | "deny"
    error_codes: list[str] = field(default_factory=list)
    reason: str = ""
    mandate_id: str | None = None
    amount_minor: int | None = None
    currency: str = "INR"
    latency_ms: float = 0.0
    provider_ref: str | None = None    # Razorpay id, when the call executed

    def line(self) -> str:
        mark = "ALLOW" if self.decision == "allow" else "DENY "
        amount = format_minor(self.amount_minor, self.currency) if self.amount_minor else "-"
        codes = ",".join(self.error_codes) or "-"
        return f"{mark} {self.tool:<20} {amount:>14}  {codes:<10} {self.latency_ms:>6.2f}ms"


class ToolDenied(Exception):
    """Raised when the gateway refuses a tool call."""

    def __init__(self, row: AuditRow):
        self.row = row
        super().__init__(f"{','.join(row.error_codes)}: {row.reason}")


class AIPGateway:
    """
    Wraps provider tools so every call is authorized before it executes.

    The agent never touches the provider directly, and never holds the key
    that signs its mandate — so it cannot widen its own authority.
    """

    def __init__(
        self,
        passport: AgentPassport,
        mandate: Mandate,
        issuer_public_key: Ed25519PublicKey,
        revocation_store: RevocationStore | None = None,
        spend_ledger: SpendLedger | None = None,
    ):
        self.passport = passport
        self.mandate = mandate
        self.issuer_public_key = issuer_public_key
        self.revocations = revocation_store or RevocationStore()
        self.ledger = spend_ledger or SpendLedger()
        self.audit: list[AuditRow] = []
        self._tools: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        """Expose a provider function to the agent under an action name."""
        self._tools[name] = fn

    @property
    def tool_names(self) -> list[str]:
        return sorted(self._tools)

    def call(self, tool: str, **params: Any) -> Any:
        """
        Authorize, then execute. Raises ToolDenied if the mandate refuses.

        Note the ordering: verification happens BEFORE the provider is
        touched. A refused call makes no network request at all.
        """
        started = time.perf_counter()
        currency = self.mandate.boundaries.monetary_limit.currency

        envelope = create_envelope(
            self.passport,
            action=tool,
            target=str(params.get("payee") or params.get("to") or "provider"),
            parameters=params,
        )
        result = verify_intent(
            sign_envelope(envelope, self.passport.private_key),
            self.passport.public_key,
            revocation_store=self.revocations,
            spend_ledger=self.ledger,
            mandate=self.mandate,
            issuer_public_key=self.issuer_public_key,
            require_mandate=True,
        )

        try:
            amount_minor = extract_amount_minor(params, currency)
        except Exception:
            amount_minor = None

        row = AuditRow(
            ts=datetime.now(timezone.utc).isoformat(),
            agent_id=self.passport.agent_id,
            tool=tool,
            parameters=params,
            decision="allow" if result.passed else "deny",
            error_codes=[e.value for e in result.errors],
            reason=result.detail,
            mandate_id=result.mandate_id,
            amount_minor=amount_minor,
            currency=currency,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )

        if not result.passed:
            self.audit.append(row)
            raise ToolDenied(row)

        # Authorized — only now does anything leave the process.
        fn = self._tools.get(tool)
        if fn is None:
            row.decision = "deny"
            row.error_codes = ["AIP-E200"]
            row.reason = f"No such tool: {tool}"
            self.audit.append(row)
            raise ToolDenied(row)

        outcome = fn(**params)
        row.provider_ref = (outcome or {}).get("id") if isinstance(outcome, dict) else None
        row.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        self.audit.append(row)
        return outcome

    # ── reporting ────────────────────────────────────────────────────────

    def metrics(self) -> dict[str, Any]:
        allows = [r for r in self.audit if r.decision == "allow"]
        denies = [r for r in self.audit if r.decision == "deny"]
        latencies = sorted(r.latency_ms for r in self.audit)

        def pct(p: float) -> float:
            if not latencies:
                return 0.0
            return latencies[min(int(len(latencies) * p), len(latencies) - 1)]

        return {
            "total_calls": len(self.audit),
            "allowed": len(allows),
            "denied": len(denies),
            "authorized_spend": format_minor(
                sum(r.amount_minor or 0 for r in allows),
                self.mandate.boundaries.monetary_limit.currency,
            ),
            "blocked_spend": format_minor(
                sum(r.amount_minor or 0 for r in denies),
                self.mandate.boundaries.monetary_limit.currency,
            ),
            "p50_ms": pct(0.50),
            "p99_ms": pct(0.99),
        }

    def export_audit(self) -> str:
        return json.dumps([asdict(r) for r in self.audit], indent=2, default=str)
