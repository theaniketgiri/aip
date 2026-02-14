/**
 * AIP-1 Cryptographic Layer — TypeScript Implementation
 *
 * Ed25519 signature verification using @noble/ed25519 v3
 * HMAC-SHA256 verification using @noble/hashes
 *
 * Note: @noble/ed25519 v3 is async — all operations return Promises.
 */

import { verify, hashes } from "@noble/ed25519";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha512 } from "@noble/hashes/sha2.js";

// @noble/ed25519 v3 requires sha512 to be configured for sync verify()
hashes.sha512 = (message: Uint8Array): Uint8Array => {
  return sha512(message);
};

// ── Base64 URL-safe encoding/decoding ─────────────────────────────

function base64urlDecode(s: string): Uint8Array {
  // Convert URL-safe base64 to standard base64
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  while (b64.length % 4 !== 0) b64 += "=";
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Hex utilities ─────────────────────────────────────────────────

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Ed25519 ───────────────────────────────────────────────────────

/**
 * Verify an Ed25519 signature.
 * @param publicKey 32-byte raw public key
 * @param data The data that was signed
 * @param signatureB64 Base64url-encoded signature
 * @returns true if signature is valid
 */
export function verifyEd25519(
  publicKey: Uint8Array,
  data: Uint8Array,
  signatureB64: string
): boolean {
  try {
    const sig = base64urlDecode(signatureB64);
    return verify(sig, data, publicKey);
  } catch {
    return false;
  }
}

// ── HMAC-SHA256 ───────────────────────────────────────────────────

/**
 * Verify an HMAC-SHA256 signature.
 * @param key 32-byte HMAC key
 * @param data The data that was signed
 * @param signatureB64 Base64url-encoded HMAC
 * @returns true if HMAC is valid
 */
export function verifyHmac(
  key: Uint8Array,
  data: Uint8Array,
  signatureB64: string
): boolean {
  try {
    const expected = hmac(sha256, key, data);
    const provided = base64urlDecode(signatureB64);
    return timingSafeEqual(expected, provided);
  } catch {
    return false;
  }
}

/**
 * Constant-time comparison to prevent timing attacks.
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
