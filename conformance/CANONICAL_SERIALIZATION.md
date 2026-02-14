# AIP-1 Canonical Serialization Specification

**Status:** Normative  
**Version:** 1.0.0  
**Date:** 2026-02-14

This document defines the **exact byte-level rules** for producing the signable payload from an AIP-1 Intent Envelope. Any implementation that does not produce byte-identical output will fail signature verification.

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

---

## 1. Overview

The signable payload is derived from the Intent Envelope by:

1. Removing the `proof` field
2. Normalizing numeric values
3. Sorting all keys recursively
4. Serializing with no whitespace
5. Encoding as UTF-8 bytes

The resulting byte array is what gets signed (Ed25519) or HMACed (Tier 0).

---

## 2. Field Exclusion

The `proof` field MUST be excluded from the signable payload. All other top-level and nested fields MUST be included, even if their value is `null`.

```
Signable = Envelope \ { "proof" }
```

---

## 3. Numeric Normalization (CRITICAL)

### 3.1 Integer Rule

Numeric values that are mathematically integers MUST be serialized **without** a decimal point.

| Value   | Correct | Incorrect |
|---------|---------|-----------|
| 500.0   | `500`   | `500.0`   |
| 0.0     | `0`     | `0.0`     |
| -50.0   | `-50`   | `-50.0`   |
| 5000.0  | `5000`  | `5000.0`  |

### 3.2 Decimal Rule

Numeric values with fractional parts MUST preserve their decimal representation.

| Value   | Correct | Incorrect |
|---------|---------|-----------|
| 45.5    | `45.5`  | `46` or `45.50` |
| 0.95    | `0.95`  | `1` or `0.950`  |
| 99.99   | `99.99` | `100`           |

### 3.3 Rationale

Python's `json.dumps(500.0)` produces `"500.0"`.  
JavaScript's `JSON.stringify(500.0)` produces `"500"`.

Without normalization, the same envelope produces different bytes in different languages, breaking cross-language signature verification.

The integer rule matches JavaScript's behavior (ECMAScript §24.5.2.1) and is consistent with RFC 7159 §6 which states numbers SHOULD NOT have unnecessary trailing zeros.

### 3.4 Implementation

**Python:**
```python
def _normalize_floats(obj):
    if isinstance(obj, dict):
        return {k: _normalize_floats(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_normalize_floats(v) for v in obj]
    elif isinstance(obj, float):
        if obj == int(obj) and not (obj != obj):  # NaN check
            return int(obj)
        return obj
    return obj
```

**JavaScript:** No normalization needed — `JSON.stringify` already produces the correct form.

**Go:**
```go
// Use json.Number or manually check:
if math.Floor(v) == v {
    return int64(v)
}
```

---

## 4. Key Ordering

All keys MUST be sorted **lexicographically** (Unicode code point order) at **every** nesting level.

### 4.1 Top-Level Order

```
@context → @type → agent → boundaries → entropy → expires_at → intent → issued_at → principal → protocol_version → ttl → verification_tier
```

Note: `@` (U+0040) sorts before all ASCII letters, so `@context` and `@type` always come first.

### 4.2 Recursive Sorting

Sorting MUST be applied recursively. For example, within `agent`:

```
attestation → id → runtime → version
```

Within `boundaries.monetary_limit`:

```
currency → per_day → per_transaction
```

### 4.3 Implementation

**Python:** `json.dumps(data, sort_keys=True)` — sorts recursively by default.

**JavaScript:** Requires a custom replacer:
```javascript
function canonicalStringify(obj) {
    if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
    if (Array.isArray(obj)) return '[' + obj.map(canonicalStringify).join(',') + ']';
    return '{' + Object.keys(obj).sort().map(k =>
        JSON.stringify(k) + ':' + canonicalStringify(obj[k])
    ).join(',') + '}';
}
```

---

## 5. Whitespace

The JSON output MUST NOT contain any whitespace between tokens.

- No spaces after `:` or `,`
- No newlines or indentation
- Equivalent to Python's `separators=(",", ":")`

| Correct | Incorrect |
|---------|-----------|
| `{"a":1,"b":2}` | `{"a": 1, "b": 2}` |
| `[1,2,3]` | `[1, 2, 3]` |

---

## 6. Datetime Serialization

All datetime values MUST be serialized as ISO 8601 strings with the `Z` suffix for UTC.

| Correct | Incorrect |
|---------|-----------|
| `"2026-02-14T12:00:00Z"` | `"2026-02-14T12:00:00+00:00"` |
| `"2026-01-01T00:00:00Z"` | `"2026-01-01T00:00:00.000Z"` |

### 6.1 Rules

- UTC times MUST use `Z` suffix, NOT `+00:00`
- Fractional seconds MUST NOT be included if they are zero
- Non-UTC timezones MUST be converted to UTC before serialization

### 6.2 Implementation

**Python (Pydantic):** Pydantic v2's `model_dump(mode="json")` serializes UTC datetimes with `Z` suffix by default.

**JavaScript:** `new Date().toISOString()` produces milliseconds (`2026-02-14T12:00:00.000Z`). You MUST strip `.000` when milliseconds are zero.

---

## 7. Null Handling

Fields with `null` values MUST be included in the canonical payload.

| Correct | Incorrect |
|---------|-----------|
| `{"expires_at":null,"issued_at":"..."}` | `{"issued_at":"..."}` (field omitted) |

Implementations MUST NOT use "omit null" or "skip empty" serialization options.

---

## 8. String Encoding

All strings MUST be UTF-8 encoded. The final canonical JSON MUST be encoded as UTF-8 bytes before signing.

Special characters in strings MUST be escaped per RFC 7159 §7:
- `"` → `\"`
- `\` → `\\`
- Control characters (U+0000 through U+001F) → `\uXXXX`

---

## 9. Array Ordering

Array elements MUST preserve their original order. Arrays are NOT sorted.

This applies to:
- `boundaries.allowed_actions`
- `boundaries.denied_actions`
- `boundaries.data_access`
- `principal.delegation_chain`

---

## 10. Nonce Format

The `entropy` field MUST conform to:

| Rule | Requirement |
|------|------------|
| **Minimum length** | 38 characters total |
| **Format** | `nonce:<hex>` where `<hex>` is ≥32 hexadecimal characters |
| **Entropy** | ≥16 bytes (128 bits) of cryptographically random data |
| **Uniqueness** | MUST be unique per envelope within a verifier's retention window |
| **Retention** | Verifiers MUST retain nonces for at least the envelope's TTL |
| **Validation error** | `AIP-E105` if nonce is too short or malformed |
| **Replay error** | `AIP-E102` if nonce was previously seen |

### 10.1 Generation

```python
import uuid
nonce = f"nonce:{uuid.uuid4().hex}"  # "nonce:a1b2c3d4..." (38 chars)
```

```javascript
import { randomUUID } from 'crypto';
const nonce = `nonce:${randomUUID().replace(/-/g, '')}`;
```

---

## 11. Complete Algorithm

```
function getSignablePayload(envelope):
    1. data = deep_copy(envelope)
    2. delete data.proof
    3. data = normalize_floats(data)      // 500.0 → 500
    4. json = serialize(data,
         sort_keys = true,                // recursive
         separators = [",", ":"],         // no whitespace
       )
    5. return utf8_encode(json)
```

---

## 12. Conformance Verification

The conformance test suite includes **Category H** vectors (H01–H05) that specifically test:

- H01: Float normalization (`500.0` → `500`)
- H02: Decimal preservation (`45.5` → `45.5`)
- H03: Key ordering (recursive lexicographic sort)
- H04: Datetime format (ISO 8601 with `Z`)
- H05: Null handling (null values present, not omitted)

Each vector includes a `canonical_payload_hex` field containing the expected byte-for-byte output. Implementations MUST produce identical bytes.

---

## 13. Reference Canonical Payload

The `_meta.reference_canonical_payload_hex` field in `vectors.json` contains the hex-encoded canonical payload for vector A01. Use this to validate your serialization implementation before running the full suite.

```python
expected = bytes.fromhex(meta["reference_canonical_payload_hex"])
actual = get_signable_payload(vectors["A01_valid_envelope"]["envelope"])
assert actual == expected, "Canonical serialization mismatch"
```
