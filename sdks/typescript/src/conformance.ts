#!/usr/bin/env node
/**
 * AIP-1 Conformance Test Runner — TypeScript Implementation
 *
 * Loads vectors.json and validates each vector against the
 * TypeScript AIP SDK. This is the second independent implementation
 * proving AIP-1 is a real protocol, not just a library.
 *
 * Usage:
 *   npx tsx src/conformance.ts           # Run all tests
 *   npx tsx src/conformance.ts --verbose  # Verbose mode
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

import type { IntentEnvelope, VerificationResult } from "./types.js";
import { AIPErrorCode } from "./types.js";
import { verifyIntent, type VerifyOptions } from "./verification.js";
import { getSignablePayloadHex } from "./canonical.js";
import { hexToBytes } from "./crypto.js";
import { RevocationStore } from "./revocation.js";

// ── Color output ──────────────────────────────────────────────────

const GREEN = "\x1b[92m";
const RED = "\x1b[91m";
const YELLOW = "\x1b[93m";
const CYAN = "\x1b[96m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";

function pass(msg: string): string {
  return `  ${GREEN}✓ PASS${RESET}  ${msg}`;
}
function failMsg(msg: string): string {
  return `  ${RED}✗ FAIL${RESET}  ${msg}`;
}

// ── Key loading ───────────────────────────────────────────────────

interface KeyMaterial {
  agent_1: Uint8Array;
  agent_2: Uint8Array;
  hmac: Uint8Array;
}

function loadKeyMaterial(meta: any): KeyMaterial {
  const km = meta.key_material;
  return {
    agent_1: hexToBytes(km.agent_1.public_key_hex),
    agent_2: hexToBytes(km.agent_2.public_key_hex),
    hmac: hexToBytes(km.hmac_key_hex),
  };
}

// ── Single vector runner ──────────────────────────────────────────

function runVector(
  vectorId: string,
  vector: any,
  keys: KeyMaterial,
  verbose: boolean
): [boolean, string] {
  const expected = vector.expected;
  const verifyKeyName: string = vector.verify_with;

  // Set up revocation store
  const store = new RevocationStore();
  const revocations: any[] = vector.revocations || [];
  for (const rev of revocations) {
    if (rev.suspended_until) {
      store.suspend(
        rev.agent_id,
        86400,
        rev.reason,
        rev.revoked_by || "system"
      );
    } else {
      store.revoke(
        rev.agent_id,
        rev.reason,
        rev.revoked_by || "system",
        rev.scope || "global"
      );
    }
  }

  // Determine key
  let hmacKey: Uint8Array | undefined;
  let publicKey: Uint8Array;

  if (verifyKeyName === "hmac") {
    hmacKey = keys.hmac;
    publicKey = keys.agent_1; // Not used for HMAC, but needed
  } else {
    publicKey = keys[verifyKeyName as keyof KeyMaterial];
  }

  const envelope: IntentEnvelope = vector.envelope;
  const requestGeo: string | undefined = vector.request_geo;

  const options: VerifyOptions = {
    publicKey,
    revocationStore: store,
    hmacKey,
    requestGeo,
  };

  let result: VerificationResult;

  // Handle replay test (verify_twice)
  if (vector.verify_twice) {
    const firstResult = verifyIntent(envelope, options);
    const expectedFirst = vector.expected_first || { valid: true };
    if (expectedFirst.valid && !firstResult.valid) {
      return [
        false,
        `First verification should have passed but got errors: ${firstResult.errors.join(", ")}`,
      ];
    }

    // Second verification — same nonce, should trigger replay
    result = verifyIntent(envelope, options);
  } else {
    result = verifyIntent(envelope, options);
  }

  // Assert results
  const failures: string[] = [];

  if ("valid" in expected) {
    if (result.valid !== expected.valid) {
      failures.push(
        `expected valid=${expected.valid}, got valid=${result.valid}`
      );
    }
  }

  if ("signature_valid" in expected) {
    if (result.signature_valid !== expected.signature_valid) {
      failures.push(
        `expected signature_valid=${expected.signature_valid}, got signature_valid=${result.signature_valid}`
      );
    }
  }

  if ("within_boundaries" in expected) {
    if (result.within_boundaries !== expected.within_boundaries) {
      failures.push(
        `expected within_boundaries=${expected.within_boundaries}, got within_boundaries=${result.within_boundaries}`
      );
    }
  }

  if ("errors" in expected) {
    const expectedErrors = new Set<string>(expected.errors);
    const actualErrors = new Set<string>(result.errors);
    for (const e of expectedErrors) {
      if (!actualErrors.has(e)) {
        failures.push(
          `expected errors ${JSON.stringify([...expectedErrors])}, got ${JSON.stringify([...actualErrors])} (missing: ${e})`
        );
        break;
      }
    }
  }

  if ("tier_used" in expected) {
    if (result.tier_used !== expected.tier_used) {
      failures.push(
        `expected tier_used=${expected.tier_used}, got tier_used=${result.tier_used}`
      );
    }
  }

  // Check canonical payload (Category H — serialization tests)
  if ("canonical_payload_hex" in vector) {
    const expectedHex: string = vector.canonical_payload_hex;
    const actualHex = getSignablePayloadHex(envelope);
    if (actualHex !== expectedHex) {
      // Find first difference
      for (let i = 0; i < Math.max(expectedHex.length, actualHex.length); i++) {
        if (expectedHex[i] !== actualHex[i]) {
          const start = Math.max(0, i - 10);
          const end = i + 10;
          failures.push(
            `canonical payload mismatch at byte ${Math.floor(i / 2)}: ` +
              `expected ...${expectedHex.slice(start, end)}... ` +
              `got ...${actualHex.slice(start, end)}...`
          );
          break;
        }
      }
      if (failures.length === 0) {
        failures.push(
          `canonical payload length mismatch: expected ${expectedHex.length / 2} bytes, got ${actualHex.length / 2}`
        );
      }
    }
  }

  if (failures.length > 0) {
    let detail = failures.join("; ");
    if (verbose) {
      detail += `\n    → Actual result: valid=${result.valid}, errors=${JSON.stringify(result.errors)}, detail=${result.detail}`;
    }
    return [false, detail];
  }

  return [true, ""];
}

// ── Main ──────────────────────────────────────────────────────────

function main(): number {
  const verbose = process.argv.includes("--verbose") || process.argv.includes("-v");
  const catFlag = process.argv.indexOf("-c");
  const categoryFilter =
    catFlag >= 0 ? process.argv[catFlag + 1] : undefined;

  // Load vectors
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const vectorsPath = resolve(__dirname, "../../../conformance/vectors.json");
  const raw = JSON.parse(readFileSync(vectorsPath, "utf-8"));

  const meta = raw._meta;
  delete raw._meta;
  const keys = loadKeyMaterial(meta);

  console.log(
    `\n${BOLD}AIP-1 Conformance Test Suite (TypeScript)${RESET}`
  );
  console.log(
    `${DIM}Spec: ${meta.spec_version} | Vectors: ${Object.keys(raw).length} | Generated: ${meta.generated_at}${RESET}`
  );
  console.log("─".repeat(70) + "\n");

  let passed = 0;
  let failed = 0;
  let skipped = 0;
  const failures: [string, string][] = [];
  const start = performance.now();

  // Group by category
  const categories = new Map<string, [string, any][]>();
  for (const [vid, vec] of Object.entries(raw)) {
    const cat = (vec as any).category || "unknown";
    if (!categories.has(cat)) categories.set(cat, []);
    categories.get(cat)!.push([vid, vec]);
  }

  for (const cat of [...categories.keys()].sort()) {
    if (categoryFilter && cat !== categoryFilter) {
      skipped += categories.get(cat)!.length;
      continue;
    }

    console.log(`${CYAN}${BOLD}  ${cat.toUpperCase()}${RESET}`);

    for (const [vid, vec] of categories.get(cat)!) {
      const [ok, detail] = runVector(vid, vec, keys, verbose);
      if (ok) {
        passed++;
        console.log(pass(verbose ? `${vid}: ${(vec as any).description?.slice(0, 60)}` : vid));
      } else {
        failed++;
        console.log(failMsg(`${vid}: ${detail}`));
        failures.push([vid, detail]);
      }
    }
    console.log();
  }

  const elapsed = performance.now() - start;

  console.log("─".repeat(70));
  const total = passed + failed;
  if (failed === 0) {
    console.log(
      `${GREEN}${BOLD}  ✓ ALL ${total} VECTORS PASSED${RESET} ${DIM}(${elapsed.toFixed(1)}ms)${RESET}`
    );
  } else {
    console.log(
      `${RED}${BOLD}  ✗ ${failed}/${total} VECTORS FAILED${RESET} ${DIM}(${elapsed.toFixed(1)}ms)${RESET}`
    );
    console.log(`\n${RED}  Failures:${RESET}`);
    for (const [vid, detail] of failures) {
      console.log(`    ${vid}: ${detail}`);
    }
  }
  if (skipped) {
    console.log(`${DIM}  (${skipped} skipped by filter)${RESET}`);
  }
  console.log();

  return failed === 0 ? 0 : 1;
}

process.exit(main());
