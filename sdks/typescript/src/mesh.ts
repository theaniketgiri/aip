/**
 * AIP Mesh Client — TypeScript
 *
 * Connects to the AIP Revocation Mesh for real-time kill switch.
 *
 * Usage:
 *   import { MeshClient } from "aip-protocol/mesh";
 *
 *   const mesh = new MeshClient("mesh_xxx_your_api_key");
 *   mesh.connect();
 *
 *   // Revoke an agent across all connected services:
 *   await mesh.revoke("did:web:acme.com:agents:rogue-bot", "gone_rogue");
 *
 *   // Check status:
 *   const status = await mesh.status("did:web:acme.com:agents:my-bot");
 */

import { RevocationStore } from "./revocation.js";

const DEFAULT_MESH_URL = "https://mesh.synthexai.tech";

export interface MeshEvent {
  type: "revocation" | "suspension" | "reinstatement";
  id: string;
  agent_id: string;
  action: string;
  reason?: string;
  scope?: string;
  suspended_until?: string;
  timestamp: string;
}

export interface MeshRevokeResponse {
  id: string;
  agent_id: string;
  action: string;
  reason: string;
  propagated_to: number;
  propagation_ms: number;
  timestamp: string;
}

export interface MeshStatusResponse {
  agent_id: string;
  status: "active" | "revoked" | "suspended";
  reason?: string;
  revoked_at?: string;
  suspended_until?: string;
}

export class MeshClient {
  private apiKey: string;
  private meshUrl: string;
  private store: RevocationStore;
  private onRevocation?: (event: MeshEvent) => void;
  private _connected = false;
  private abortController?: AbortController;

  constructor(
    apiKey: string,
    options: {
      meshUrl?: string;
      store?: RevocationStore;
      onRevocation?: (event: MeshEvent) => void;
    } = {}
  ) {
    this.apiKey = apiKey;
    this.meshUrl = (options.meshUrl || DEFAULT_MESH_URL).replace(/\/$/, "");
    this.store = options.store || new RevocationStore();
    this.onRevocation = options.onRevocation;
  }

  /**
   * Start receiving real-time revocation events from the mesh.
   */
  async connect(): Promise<this> {
    if (this._connected) return this;

    this.abortController = new AbortController();
    this._connected = true;

    // Start SSE listener in background
    this.sseLoop();

    return this;
  }

  /**
   * Stop receiving events.
   */
  disconnect(): void {
    this.abortController?.abort();
    this._connected = false;
  }

  private async sseLoop(): Promise<void> {
    while (this._connected) {
      try {
        const response = await fetch(`${this.meshUrl}/mesh/events`, {
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            Accept: "text/event-stream",
          },
          signal: this.abortController?.signal,
        });

        if (!response.ok || !response.body) {
          throw new Error(`SSE connection failed: ${response.status}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (this._connected) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith("data: ")) {
              try {
                const event: MeshEvent = JSON.parse(trimmed.slice(6));
                this.handleEvent(event);
              } catch {
                // Skip malformed events
              }
            }
          }
        }
      } catch (err) {
        if (!this._connected) break;
        // Reconnect after backoff
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  }

  private handleEvent(event: MeshEvent): void {
    if (event.type === "revocation") {
      this.store.revoke(
        event.agent_id,
        event.reason || "mesh_revocation",
        "mesh",
        event.scope || "global"
      );
    } else if (event.type === "suspension") {
      if (event.suspended_until) {
        const until = new Date(event.suspended_until);
        const now = new Date();
        const duration = Math.max(1, Math.floor((until.getTime() - now.getTime()) / 1000));
        this.store.suspend(event.agent_id, duration, event.reason || "mesh_suspension");
      }
    } else if (event.type === "reinstatement") {
      // RevocationStore doesn't have reinstate — just clear by re-creating
      // In a full impl, we'd add reinstate() to the store
    }

    this.onRevocation?.(event);
  }

  // ── REST API calls ──────────────────────────────────────────────

  private async apiCall<T>(endpoint: string, data: Record<string, unknown>): Promise<T> {
    const resp = await fetch(`${this.meshUrl}${endpoint}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });
    if (!resp.ok) {
      const error = await resp.text();
      throw new Error(`Mesh API error (${resp.status}): ${error}`);
    }
    return resp.json() as Promise<T>;
  }

  /**
   * Revoke an agent via the mesh (broadcasts to all connected clients).
   */
  async revoke(
    agentId: string,
    reason = "manual_revocation",
    scope = "global"
  ): Promise<MeshRevokeResponse> {
    const result = await this.apiCall<MeshRevokeResponse>("/mesh/revoke", {
      agent_id: agentId,
      reason,
      scope,
    });
    this.store.revoke(agentId, reason, "mesh", scope);
    return result;
  }

  /**
   * Suspend an agent temporarily via the mesh.
   */
  async suspend(
    agentId: string,
    durationSeconds = 1800,
    reason = "auto_suspend"
  ): Promise<MeshRevokeResponse> {
    const result = await this.apiCall<MeshRevokeResponse>("/mesh/suspend", {
      agent_id: agentId,
      duration_seconds: durationSeconds,
      reason,
    });
    this.store.suspend(agentId, durationSeconds, reason);
    return result;
  }

  /**
   * Check an agent's revocation status on the mesh.
   */
  async status(agentId: string): Promise<MeshStatusResponse> {
    return this.apiCall<MeshStatusResponse>("/mesh/status", {
      agent_id: agentId,
    });
  }

  /**
   * Reinstate a revoked/suspended agent via the mesh.
   */
  async reinstate(agentId: string): Promise<{ agent_id: string; status: string }> {
    return this.apiCall("/mesh/reinstate", { agent_id: agentId });
  }

  /**
   * Register an agent on the mesh (counts against tier limit).
   */
  async registerAgent(agentId: string): Promise<Record<string, unknown>> {
    return this.apiCall("/mesh/agents/register", { agent_id: agentId });
  }

  /**
   * Get current month's usage and tier info.
   */
  async usage(): Promise<Record<string, unknown>> {
    const resp = await fetch(`${this.meshUrl}/mesh/usage`, {
      headers: { Authorization: `Bearer ${this.apiKey}` },
    });
    return resp.json();
  }

  get connected(): boolean {
    return this._connected;
  }
}
