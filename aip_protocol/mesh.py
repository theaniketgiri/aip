"""
AIP Mesh Client — Connects local RevocationStore to the cloud mesh.

Usage:
    from aip_protocol.mesh import MeshClient

    mesh = MeshClient("mesh_xxx_your_api_key")
    mesh.connect()

    # Now your local revocation store auto-updates in real-time.
    # When someone revokes an agent via the mesh API, your local
    # store gets the update within <50ms.

    # You can also revoke from code:
    mesh.revoke("did:web:acme.com:agents:rogue-bot", reason="gone_rogue")
    mesh.suspend("did:web:acme.com:agents:suspicious", duration=1800)

    # Check status:
    status = mesh.status("did:web:acme.com:agents:my-bot")
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Callable
from urllib.request import Request, urlopen
from urllib.error import URLError

from aip_protocol.revocation import RevocationStore


DEFAULT_MESH_URL = "https://mesh.synthexai.tech"


class MeshClient:
    """
    Connects a local RevocationStore to the AIP Revocation Mesh.

    On connect(), starts a background thread that receives real-time
    revocation events and applies them to your local store.

    API calls (revoke, suspend, status) go through REST.
    Real-time updates come through SSE (Server-Sent Events).
    """

    def __init__(
        self,
        api_key: str,
        mesh_url: str = DEFAULT_MESH_URL,
        store: RevocationStore | None = None,
        on_revocation: Callable[[dict], None] | None = None,
    ):
        self.api_key = api_key
        self.mesh_url = mesh_url.rstrip("/")
        self.store = store or RevocationStore()
        self.on_revocation = on_revocation
        self._connected = False
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def connect(self) -> "MeshClient":
        """Start receiving real-time revocation events from the mesh."""
        if self._connected:
            return self

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._sse_loop,
            daemon=True,
            name="aip-mesh-client",
        )
        self._thread.start()
        self._connected = True
        return self

    def disconnect(self):
        """Stop receiving events."""
        self._stop.set()
        self._connected = False

    def _sse_loop(self):
        """Background SSE listener with auto-reconnect."""
        while not self._stop.is_set():
            try:
                req = Request(
                    f"{self.mesh_url}/mesh/events",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Accept": "text/event-stream",
                    },
                )
                with urlopen(req, timeout=60) as resp:
                    for line in resp:
                        if self._stop.is_set():
                            break
                        line = line.decode("utf-8").strip()
                        if line.startswith("data: "):
                            try:
                                event = json.loads(line[6:])
                                self._handle_event(event)
                            except json.JSONDecodeError:
                                pass
            except (URLError, OSError, TimeoutError):
                # Reconnect after backoff
                if not self._stop.is_set():
                    self._stop.wait(5.0)

    def _handle_event(self, event: dict):
        """Apply a mesh event to the local RevocationStore."""
        event_type = event.get("type", "")
        agent_id = event.get("agent_id", "")

        if event_type == "revocation":
            self.store.revoke(
                agent_id=agent_id,
                reason=event.get("reason", "mesh_revocation"),
                revoked_by=event.get("revoked_by", "mesh"),
                scope=event.get("scope", "global"),
            )
        elif event_type == "suspension":
            suspended_until = event.get("suspended_until", "")
            if suspended_until:
                until_dt = datetime.fromisoformat(suspended_until)
                now = datetime.now(timezone.utc)
                duration = max(1, int((until_dt - now).total_seconds()))
                self.store.suspend(
                    agent_id=agent_id,
                    duration_seconds=duration,
                    reason=event.get("reason", "mesh_suspension"),
                )
        elif event_type == "reinstatement":
            self.store.reinstate(agent_id)

        # Call user callback if set
        if self.on_revocation:
            try:
                self.on_revocation(event)
            except Exception:
                pass

    # ── REST API calls ─────────────────────────────────────────────

    def _api_call(self, endpoint: str, data: dict) -> dict:
        """Make an authenticated API call to the mesh."""
        body = json.dumps(data).encode("utf-8")
        req = Request(
            f"{self.mesh_url}{endpoint}",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def revoke(self, agent_id: str, reason: str = "manual_revocation", scope: str = "global") -> dict:
        """Revoke an agent via the mesh (broadcasts to all connected clients)."""
        result = self._api_call("/mesh/revoke", {
            "agent_id": agent_id,
            "reason": reason,
            "scope": scope,
        })
        # Also apply locally immediately
        self.store.revoke(agent_id, reason, "mesh", scope)
        return result

    def suspend(self, agent_id: str, duration: int = 1800, reason: str = "auto_suspend") -> dict:
        """Suspend an agent temporarily via the mesh."""
        result = self._api_call("/mesh/suspend", {
            "agent_id": agent_id,
            "duration_seconds": duration,
            "reason": reason,
        })
        self.store.suspend(agent_id, duration, reason)
        return result

    def status(self, agent_id: str) -> dict:
        """Check an agent's revocation status on the mesh."""
        return self._api_call("/mesh/status", {"agent_id": agent_id})

    def reinstate(self, agent_id: str) -> dict:
        """Reinstate a revoked/suspended agent via the mesh."""
        result = self._api_call("/mesh/reinstate", {"agent_id": agent_id})
        self.store.reinstate(agent_id)
        return result

    def register_agent(self, agent_id: str) -> dict:
        """Register an agent on the mesh (counts against tier limit)."""
        return self._api_call("/mesh/agents/register", {"agent_id": agent_id})

    def usage(self) -> dict:
        """Get current month's usage and tier info."""
        req = Request(
            f"{self.mesh_url}/mesh/usage",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    @property
    def connected(self) -> bool:
        return self._connected
