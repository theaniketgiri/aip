/**
 * AIP-1 Revocation Store — TypeScript Implementation
 *
 * In-memory revocation tracking with nonce replay detection.
 * Matches the Python RevocationStore API exactly.
 */

import type { RevocationRecord } from "./types.js";

export class RevocationStore {
  private revocations = new Map<string, RevocationRecord>();
  private nonceCache = new Set<string>();
  private _lastSync: Date = new Date();

  static readonly MAX_NONCE_CACHE = 100_000;

  get lastSyncTime(): Date {
    return this._lastSync;
  }

  touchSync(): void {
    this._lastSync = new Date();
  }

  /**
   * Revoke an agent globally.
   */
  revoke(
    agentId: string,
    reason = "manual_revocation",
    revokedBy = "unknown",
    scope = "global"
  ): RevocationRecord {
    const record: RevocationRecord = {
      agent_id: agentId,
      reason,
      revoked_at: new Date().toISOString(),
      revoked_by: revokedBy,
      scope,
      suspended_until: null,
    };
    this.revocations.set(agentId, record);
    this._lastSync = new Date();
    return record;
  }

  /**
   * Temporarily suspend an agent.
   */
  suspend(
    agentId: string,
    durationSeconds = 1800,
    reason = "auto_suspend",
    revokedBy = "circuit_breaker"
  ): RevocationRecord {
    const now = new Date();
    const until = new Date(now.getTime() + durationSeconds * 1000);
    const record: RevocationRecord = {
      agent_id: agentId,
      reason,
      revoked_at: now.toISOString(),
      revoked_by: revokedBy,
      scope: "global",
      suspended_until: until.toISOString(),
    };
    this.revocations.set(agentId, record);
    this._lastSync = new Date();
    return record;
  }

  /**
   * Check if an agent is currently revoked or suspended.
   */
  isRevoked(agentId: string): boolean {
    const record = this.revocations.get(agentId);
    if (!record) return false;

    // Check if suspension has expired
    if (record.suspended_until) {
      const until = new Date(record.suspended_until);
      if (new Date() > until) {
        this.revocations.delete(agentId);
        return false;
      }
    }

    return true;
  }

  /**
   * Check if an agent is specifically suspended (not permanently revoked).
   */
  isSuspended(agentId: string): boolean {
    const record = this.revocations.get(agentId);
    if (!record) return false;
    return record.suspended_until !== null;
  }

  /**
   * Check if a nonce has been seen before (replay detection).
   * Returns true if nonce is NEW (not a replay).
   * Returns false if nonce was already used.
   */
  checkNonce(nonce: string): boolean {
    if (this.nonceCache.has(nonce)) {
      return false; // Replay detected
    }

    // Bound the cache
    if (this.nonceCache.size >= RevocationStore.MAX_NONCE_CACHE) {
      const evictCount = Math.floor(RevocationStore.MAX_NONCE_CACHE / 10);
      const iter = this.nonceCache.values();
      for (let i = 0; i < evictCount; i++) {
        const val = iter.next().value;
        if (val !== undefined) this.nonceCache.delete(val);
      }
    }

    this.nonceCache.add(nonce);
    return true; // New nonce, OK
  }

  /**
   * Clear the nonce cache.
   */
  clearNonces(): void {
    this.nonceCache.clear();
  }

  get revocationCount(): number {
    return this.revocations.size;
  }
}
