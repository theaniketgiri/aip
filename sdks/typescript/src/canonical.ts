/**
 * AIP-1 Canonical Serialization — TypeScript Implementation
 *
 * This module produces byte-identical output to the Python SDK's
 * _get_signable_payload(). If even one byte differs, signatures break.
 *
 * Rules (from CANONICAL_SERIALIZATION.md):
 *   1. Remove "proof" field
 *   2. Normalize floats: whole numbers → integers (500.0 → 500)
 *   3. Sort keys recursively (lexicographic)
 *   4. No whitespace (compact JSON)
 *   5. Encode as UTF-8 bytes
 */

import type { IntentEnvelope } from "./types.js";

/**
 * Normalize a value for canonical serialization.
 * - Whole floats → integers (500.0 → 500)
 * - Non-whole floats preserved (45.5 → 45.5)
 * - Recursively normalizes objects and arrays
 * - null stays null (not omitted)
 */
function normalizeValue(value: unknown): unknown {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === "number") {
    // Whole numbers → integer representation
    // JSON.stringify in JS already does this natively (500.0 → "500")
    // but we normalize explicitly for clarity
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(normalizeValue);
  }
  if (typeof value === "object") {
    const normalized: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>)) {
      normalized[key] = normalizeValue(
        (value as Record<string, unknown>)[key]
      );
    }
    return normalized;
  }
  return value;
}

/**
 * Recursively sort all keys in an object lexicographically.
 * Arrays preserve order. Handles nested objects.
 */
function sortKeysRecursive(obj: unknown): unknown {
  if (obj === null || obj === undefined) {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(sortKeysRecursive);
  }
  if (typeof obj === "object") {
    const sorted: Record<string, unknown> = {};
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    for (const key of keys) {
      sorted[key] = sortKeysRecursive(
        (obj as Record<string, unknown>)[key]
      );
    }
    return sorted;
  }
  return obj;
}

/**
 * Get the canonical signable payload from an IntentEnvelope.
 *
 * This MUST produce byte-identical output to the Python SDK's
 * _get_signable_payload() function.
 *
 * @param envelope The full envelope (including proof)
 * @returns UTF-8 bytes of the canonical JSON
 */
export function getSignablePayload(envelope: IntentEnvelope): Uint8Array {
  // Step 1: Remove proof
  const { proof, ...rest } = envelope;

  // Step 2: Normalize floats (JS does this natively, but explicit)
  const normalized = normalizeValue(rest);

  // Step 3: Sort keys recursively
  const sorted = sortKeysRecursive(normalized);

  // Step 4: Compact JSON (no whitespace)
  const canonical = JSON.stringify(sorted);

  // Step 5: UTF-8 encode
  return new TextEncoder().encode(canonical);
}

/**
 * Get the canonical payload as a hex string (for debugging/comparison).
 */
export function getSignablePayloadHex(envelope: IntentEnvelope): string {
  const bytes = getSignablePayload(envelope);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
