/**
 * AIP-1 Agent Intent Protocol — TypeScript SDK
 *
 * The second independent implementation of AIP-1.
 * Passes all 31 conformance vectors byte-identically with the
 * reference Python SDK.
 *
 * @module aip-protocol
 */

export * from "./types.js";
export { getSignablePayload, getSignablePayloadHex } from "./canonical.js";
export { verifyEd25519, verifyHmac, hexToBytes, bytesToHex } from "./crypto.js";
export { RevocationStore } from "./revocation.js";
export { verifyIntent, type VerifyOptions } from "./verification.js";
