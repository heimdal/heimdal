# Heimdal JSON Printer vs. JER (X.697) — Divergence Analysis

## Overview

ITU-T Recommendation X.697 (also published as ISO/IEC 8825-8) specifies the
**JSON Encoding Rules (JER)** for ASN.1. The latest edition is X.697
(02/2021). JER defines how each ASN.1 type maps to a JSON representation,
enabling ASN.1 data to be serialized as standard JSON (ECMA 404 / RFC 8259).

This document compares Heimdal's current JSON printer (in `gen_print.c` and
`template.c`) against the JER specification, identifying divergences that
would need to be addressed for JER compliance.

## Type-by-Type JER Reference

### 1. BOOLEAN

**JER:** JSON literal `true` or `false` (unquoted).

```json
true
false
```

**Heimdal status:** Compliant.

### 2. INTEGER

**JER:** JSON number (no fractional part, no exponent). Named values
(e.g., `INTEGER { low(0), medium(1), high(2) }`) receive no special
treatment — the numeric value is always used, not the name.

```json
42
-7
```

Large integers exceeding JSON number precision may be encoded as JSON strings.

**Heimdal divergence:** Heimdal emits the symbolic name string when a named
value matches. JER always uses the numeric value.

### 3. ENUMERATED

**JER:** JSON string containing the enumeration identifier name.

```json
"green"
```

**Heimdal divergence:** Heimdal emits the name when known (which matches),
but falls through to a bare number when the value doesn't match a known name.
JER always requires the identifier name string.

### 4. BIT STRING

JER encoding varies based on whether the type has named bits and whether it
is fixed-size or variable-size (X.697 Section 24).

#### 4a. Named Bits — JSON object with booleans

JER encodes as a JSON object where each named bit is a property with a
boolean value:

```json
{ "read": true, "write": false, "execute": true }
```

**Heimdal divergence:** Heimdal emits an array listing only the set bit
names: `["read", "execute"]`. JER requires a JSON object with boolean values
for **every** named bit.

#### 4b. Fixed-size BIT STRING (no named bits) — hex string

```json
"A0FF"
```

#### 4c. Variable-size BIT STRING (no named bits) — JSON object

```json
{ "value": "A0", "length": 5 }
```

**Heimdal divergence:** Heimdal packs the bit count and hex into a single
colon-separated string: `"5:a0"`. JER uses a structured object with `value`
and `length` keys.

#### 4d. BIT STRING with contents constraint

The 2021 revision allows encoding the contained type directly using a
`"containing"` key.

### 5. OCTET STRING

**JER:** JSON string of hexadecimal digits.

```json
"48656C6C6F"
```

With the `[BASE64]` encoding instruction, encodes as a Base64 string instead.

**Heimdal divergence:** Both use hex encoding, but Heimdal applies
`rk_strasvis(VIS_CSTYLE)` on top, which could produce non-standard escaping.
In practice hex digits are safe, so this is largely cosmetic.

### 6. NULL

**JER:** JSON literal `null`.

**Heimdal status:** Compliant.

### 7. OBJECT IDENTIFIER

**JER:** Plain JSON string using dot-separated numeric notation.

```json
"1.2.840.113549"
```

**Heimdal divergence (major):** Heimdal emits a rich JSON object:

```json
{
  "_type": "OBJECT IDENTIFIER",
  "oid": "1.2.3",
  "components": [1, 2, 3],
  "name": "foo"
}
```

JER requires just the dotted-numeric string.

### 8. String Types

**JER:** All ASN.1 string types (UTF8String, IA5String, PrintableString,
VisibleString, GeneralString, NumericString, BMPString, UniversalString,
TeletexString, GraphicString, ObjectDescriptor) are encoded as JSON strings.
Non-ASCII characters use standard JSON Unicode escapes (`\uXXXX`).

```json
"Hello, World!"
```

**Heimdal divergence:** Heimdal uses BSD `vis(3)` C-style escaping (`\xHH`
for non-printable characters). The `\xHH` sequences are not valid JSON.
JER requires standard JSON Unicode escapes (`\uXXXX`).

### 9. GeneralizedTime

**JER:** JSON string in ASN.1 basic format (no dashes, no colons, no "T"
separator):

```json
"20250222153045Z"
```

**Heimdal divergence:** Heimdal uses ISO 8601 extended format with
separators:

```json
"2025-02-22T15:30:45Z"
```

### 10. UTCTime

**JER:** JSON string in ASN.1 compact format (two-digit year):

```json
"250222153045Z"
```

**Heimdal divergence:** Same as GeneralizedTime — Heimdal uses ISO 8601
extended format.

### 11. REAL

**JER:** Finite values are JSON numbers. Special values are JSON strings:

| ASN.1 Value | JER |
|---|---|
| Finite | `3.14` |
| PLUS-INFINITY | `"PLUS-INFINITY"` |
| MINUS-INFINITY | `"MINUS-INFINITY"` |
| NOT-A-NUMBER | `"NOT-A-NUMBER"` |

### 12. SEQUENCE / SET

**JER:** JSON object. Property names are the ASN.1 component identifiers.
OPTIONAL components that are absent are simply **omitted** from the object.

```json
{ "name": "Alice", "age": 30, "active": true }
```

**Heimdal divergence:**

- Heimdal adds `_type` (type name) and `_save` (hex DER when
  `A1_HF_PRESERVE` is set) metadata fields. JER objects contain only
  ASN.1-defined member names.
- For absent OPTIONAL members, Heimdal emits `"field": null`. JER omits
  the property entirely.

### 13. SEQUENCE OF / SET OF

**JER:** JSON array.

```json
["Alice", "Bob", "Charlie"]
```

With the `[OBJECT]` encoding instruction on SET OF (of 2-component SEQUENCE),
encodes as a JSON object (key-value dictionary).

**Heimdal status:** Compliant for the default array encoding.

### 14. CHOICE

**JER:** JSON object with a **single property** whose key is the chosen
alternative's identifier and whose value is the alternative's encoding.

```json
{ "success": "OK" }
{ "error": 404 }
```

**Heimdal divergence (major):** Heimdal uses a two-property object with
fixed keys:

```json
{ "_choice": "success", "value": "OK" }
```

JER uses one property whose key **is** the alternative name.

### 15. Tagged Types

**JER:** Tags are transparent — they do not affect the JSON encoding. A
tagged type is encoded identically to its underlying base type.

**Heimdal status:** Compliant.

### 16. Open Types (ANY / HEIM_ANY)

**JER:** When the actual type is known, encodes the value inline as if it
were that type — no wrapper, no choice key.

**Heimdal divergence:** Heimdal uses underscore-prefixed sibling fields in
the parent object (`_params_choice`, `_params`). To achieve JER compliance,
promote the decoded open type fields directly into the containing structure.

### 17. HEIM_INTEGER (big integers)

**JER:** JSON number (string fallback for very large values exceeding JSON
number precision).

**Heimdal divergence:** Heimdal always hex-encodes big integers:
`"deadbeef"` or `"-deadbeef"`.

## JER Encoding Instructions

X.697 defines six encoding instructions (clauses 14–19):

| Instruction | Clause | Target Types | Effect |
|---|---|---|---|
| **ARRAY** | 14 | SEQUENCE, SET | Encode as JSON array instead of object |
| **BASE64** | 15 | OCTET STRING | Encode as Base64 instead of hex |
| **NAME** | 16 | Components of SEQUENCE, SET, CHOICE | Change JSON property name |
| **OBJECT** | 17 | SET OF (of 2-component SEQUENCE) | Encode as JSON object (key-value dictionary) |
| **TEXT** | 18 | ENUMERATED, BOOLEAN, NULL | Change text representation |
| **UNWRAPPED** | 19 | CHOICE | Remove wrapping JSON object |

## Divergence Summary

| Divergence | Severity | Difficulty |
|---|---|---|
| OID as rich object vs. dotted string | High | Easy |
| CHOICE wrapper (`_choice`/`value` vs single-key) | High | Medium |
| BIT STRING (named + unnamed formats) | High | Medium |
| Time formats (ISO 8601 extended vs. ASN.1 compact) | High | Easy |
| `_type`/`_save` metadata in SEQUENCE | Medium | Easy (just omit) |
| OPTIONAL as `null` vs. omitted | Medium | Easy |
| String VIS escaping vs. JSON `\uXXXX` | Medium | Medium |
| Named INTEGER values (name vs. number) | Low | Easy |
| ENUMERATED fallback to number | Low | Easy |
| Open type encoding | Medium | Easy (promote decoded fields to parent) |
| HEIM_INTEGER hex vs. number | Low | Medium |

The biggest structural divergences are OID representation, CHOICE encoding,
BIT STRING encoding, and time formats. The `_type` metadata and
OPTIONAL-as-null are easy to toggle. The string escaping issue (`\xHH` vs
`\uXXXX`) affects JSON validity and would need attention. Open type encoding
is straightforward: promote the decoded open type fields directly into the
containing structure rather than using underscore-prefixed sibling keys.
