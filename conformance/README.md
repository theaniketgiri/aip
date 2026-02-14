# AIP-1 Conformance Test Suite

Language-agnostic test vectors for validating **any** AIP-1 implementation.

If your SDK passes these 25 vectors, it speaks AIP-1 correctly.

## Quick Start (Python Reference)

```bash
# From the repo root
python conformance/run_conformance.py

# Verbose mode — shows each test description
python conformance/run_conformance.py -v

# Run a single category
python conformance/run_conformance.py -c boundary

# Run a single test
python conformance/run_conformance.py B03
```

## What's Tested

| Category | Vectors | What it proves |
|----------|---------|----------------|
| **A — Envelope Validity** | 4 | Version check, schema check, expiry |
| **B — Signature** | 4 | Ed25519, wrong key, tampered payload, HMAC Tier 0 |
| **C — Replay Detection** | 2 | Unique nonce passes, duplicate nonce rejected |
| **D — Boundary Enforcement** | 7 | Allowed/denied actions, monetary limits, geo restriction |
| **E — Revocation** | 4 | Not revoked, revoked, revoked-at-Tier-0, suspended |
| **F — Tiered Verification** | 2 | Tier 0 skips attestation, tier escalation |
| **G — Edge Cases** | 2 | Zero amount, negative amount |

**Total: 25 vectors across 7 categories**

## Architecture

```
conformance/
├── README.md              ← You are here
├── generate_vectors.py    ← Generates vectors.json from fixed seeds
├── run_conformance.py     ← Python runner (reference implementation)
└── vectors.json           ← THE test vectors (language-agnostic JSON)
```

### `vectors.json` — The Source of Truth

Every vector contains:

```json
{
  "A01_valid_envelope": {
    "description": "A correctly formed and signed envelope MUST pass verification.",
    "category": "envelope_validity",
    "envelope": { ... },         // Full signed IntentEnvelope
    "verify_with": "agent_1",   // Which key to verify with
    "expected": {
      "valid": true,
      "signature_valid": true,
      "within_boundaries": true,
      "errors": []
    }
  }
}
```

The `_meta` section contains:
- **Key material** — Fixed Ed25519 keypairs (hex + base64url) and HMAC key
- **Canonical serialization spec** — Exactly how to produce the signable payload
- **Reference canonical payload** — Hex-encoded bytes for cross-checking

### Key Material (Deterministic)

All vectors use these fixed keys (NOT for production):

| Key | Seed (hex) | Purpose |
|-----|-----------|---------|
| `agent_1` | `aa...aa` (32 bytes) | Primary signer |
| `agent_2` | `bb...bb` (32 bytes) | Wrong-key tests |
| `hmac` | `cc...cc` (32 bytes) | Tier 0 HMAC tests |

## Implementing for Another Language

To validate your TypeScript/Go/Rust/Java AIP-1 implementation:

### Step 1: Load `vectors.json`

```typescript
const vectors = JSON.parse(fs.readFileSync('conformance/vectors.json', 'utf8'));
const meta = vectors._meta;
```

### Step 2: Reconstruct Keys

```typescript
const agent1PubKey = Buffer.from(meta.key_material.agent_1.public_key_hex, 'hex');
const agent2PubKey = Buffer.from(meta.key_material.agent_2.public_key_hex, 'hex');
const hmacKey = Buffer.from(meta.key_material.hmac_key_hex, 'hex');
```

### Step 3: Canonical Serialization

The signable payload MUST be computed as:

1. Take the envelope object
2. Remove the `proof` field
3. `JSON.stringify` with **sorted keys**, **no whitespace** (`separators=(',', ':')`)
4. Encode as **UTF-8 bytes**

```typescript
function getSignablePayload(envelope: object): Buffer {
  const { proof, ...rest } = envelope;
  const canonical = JSON.stringify(rest, Object.keys(rest).sort());
  // NOTE: Must recursively sort ALL nested keys
  return Buffer.from(canonical, 'utf-8');
}
```

### Step 4: Run Each Vector

```typescript
for (const [id, vector] of Object.entries(vectors)) {
  if (id.startsWith('_')) continue;
  
  const envelope = deserialize(vector.envelope);
  const key = vector.verify_with === 'agent_1' ? agent1PubKey : agent2PubKey;
  const result = verifyIntent(envelope, key, { hmacKey, revocations: vector.revocations });
  
  assert(result.valid === vector.expected.valid, `${id} failed`);
  if (vector.expected.errors) {
    assert(vector.expected.errors.every(e => result.errors.includes(e)));
  }
}
```

### Step 5: Cross-Check Canonical Payload

Use `_meta.reference_canonical_payload_hex` to verify your serialization matches:

```typescript
const expected = Buffer.from(meta.reference_canonical_payload_hex, 'hex');
const actual = getSignablePayload(vectors.A01_valid_envelope.envelope);
assert(actual.equals(expected), 'Canonical serialization mismatch!');
```

## Special Vector Types

### Replay Tests (`verify_twice: true`)

Some vectors must be verified **twice** against the same nonce store:

```python
# First verification — should pass
result1 = verify(envelope, store)
assert result1.valid == vector["expected_first"]["valid"]

# Second verification — same nonce, should fail
result2 = verify(envelope, store)
assert result2.valid == vector["expected"]["valid"]  # False
assert "AIP-E102" in result2.errors
```

### Revocation Tests (`revocations: [...]`)

Load revocation records into the store before verification:

```python
for rev in vector["revocations"]:
    if rev["suspended_until"]:
        store.suspend(rev["agent_id"])
    else:
        store.revoke(rev["agent_id"])
```

### Geo Tests (`request_geo: "US"`)

Pass the `request_geo` parameter to the verifier.

## Regenerating Vectors

If you modify the SDK's canonical serialization, regenerate:

```bash
python conformance/generate_vectors.py
python conformance/run_conformance.py -v  # Validate
```

Vectors are deterministic — same seeds always produce same output.

## AIP-1 Compliance Badge

If all 25 vectors pass, your implementation is **AIP-1 Conformant**:

```
✓ AIP-1 Conformant — 25/25 vectors passed
```

## Error Code Reference

| Code | Meaning | Tested In |
|------|---------|-----------|
| AIP-E100 | Invalid signature | B02, B03 |
| AIP-E101 | Expired envelope | A02 |
| AIP-E102 | Replay detected | C02 |
| AIP-E103 | Schema invalid | A04 |
| AIP-E104 | Version unsupported | A03 |
| AIP-E200 | Action not allowed | D02 |
| AIP-E201 | Action denied | D03 |
| AIP-E202 | Monetary limit exceeded | D05 |
| AIP-E204 | Geo restriction violated | D07 |
| AIP-E400 | Agent revoked | E02, E03 |
| AIP-E401 | Agent suspended | E04 |
