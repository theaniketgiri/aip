# AIP-1 TypeScript SDK

The second independent implementation of the Agent Intent Protocol (AIP-1).

**31/31 conformance vectors passing** — byte-identical to the reference Python SDK.

## Installation

```bash
npm install aip-protocol
```

## Quick Start

```typescript
import { verifyIntent, RevocationStore, hexToBytes } from "aip-protocol";

const result = verifyIntent(envelope, {
  publicKey: hexToBytes("e734ea6c..."),
  revocationStore: new RevocationStore(),
});

if (result.valid) {
  console.log("✓ Intent verified");
} else {
  console.log("✗ Failed:", result.errors, result.detail);
}
```

## Architecture

```
src/
  types.ts        — TypeScript interfaces (IntentEnvelope, VerificationResult, etc.)
  canonical.ts    — Canonical serialization (byte-identical to Python)
  crypto.ts       — Ed25519 + HMAC-SHA256 via @noble/ed25519
  revocation.ts   — In-memory revocation store with nonce replay detection
  verification.ts — Full 8-step verification pipeline
  conformance.ts  — Conformance test runner (31 vectors)
  index.ts        — Barrel exports
```

## Conformance

```bash
npx tsx src/conformance.ts
```

Expected output:
```
AIP-1 Conformance Test Suite (TypeScript)
──────────────────────────────────────────
  ✓ ALL 31 VECTORS PASSED (90.4ms)
```

## Dependencies

- `@noble/ed25519` v3 — Ed25519 signatures (RFC 8032)
- `@noble/hashes` v2 — SHA-256, SHA-512, HMAC
- Zero other dependencies

## License

MIT
