# Plan: Add JSON-to-C-type Parsing to ASN.1 Template System

## Overview

Add `_asn1_parse_json()` — a new template interpreter in `template.c` that is
the inverse of `_asn1_print()`.  This enables parsing the JSON produced by
`print_<TYPE>()` back into C types, completing a JSON round-trip:

    C struct → print_<TYPE>() → JSON string → asn1_parse_<TYPE>() → C struct

## JSON Format Reference (produced by `_asn1_print`)

| ASN.1 construct        | JSON output format                                              |
|------------------------|-----------------------------------------------------------------|
| SEQUENCE/SET           | `{"_type":"TypeName","field1":val,...}`                          |
| CHOICE                 | `{"_choice":"altName","value":...}`                             |
| SEQUENCE OF / SET OF   | `[elem, elem, ...]`                                             |
| INTEGER/UNSIGNED       | bare number: `42`                                               |
| INTEGER64/UNSIGNED64   | bare number: `42`                                               |
| heim_integer           | quoted hex: `"0a1b2c"` or `"-0a1b2c"`                          |
| BOOLEAN                | bare: `true` / `false`                                          |
| NULL                   | bare: `null`                                                    |
| ENUMERATION (named)    | quoted name: `"symbolicName"`                                   |
| ENUMERATION (unnamed)  | bare number: `42`                                               |
| GeneralString/UTF8/etc | quoted string: `"hello"`                                        |
| OCTET STRING           | quoted hex: `"deadbeef"`                                        |
| BIT STRING (raw)       | quoted: `"64:0a1b"` (bitcount:hex)                              |
| BIT STRING (named)     | array of names: `["bit1","bit2"]`                               |
| OID                    | object: `{"_type":"OBJECT IDENTIFIER","oid":"1.2.3",...}`       |
| GeneralizedTime/UTC    | quoted: `"2024-01-15T12:00:00Z"`                                |
| OPTIONAL (absent)      | `null`                                                          |

## Files to Modify

### 1. `lib/asn1/template.c` — Core interpreter (bulk of the work)

Add ~600-800 lines:

- `_asn1_parse_json_prim()` — static helper to parse a JSON value into a
  primitive C type, keyed on `enum template_types`.  Handles all 22 primitive
  types (A1T_INTEGER, A1T_OCTET_STRING, A1T_OID, A1T_BOOLEAN, etc.).

- `_asn1_parse_json()` — recursive template interpreter, mirrors
  `_asn1_print()` structure exactly.  For each template entry:
  - **A1_OP_NAME**: Collect field names (same traversal as `_asn1_print`)
  - **A1_OP_DEFVAL**: Remember default template entry
  - **A1_OP_TYPE / A1_OP_TYPE_EXTERN**: Recurse with JSON sub-object
  - **A1_OP_TAG**: Transparent in JSON — just recurse into `t->ptr`
  - **A1_OP_PARSE**: Call `_asn1_parse_json_prim()` for the field's JSON value
  - **A1_OP_SEQOF / A1_OP_SETOF**: Iterate JSON array, allocate `template_of`,
    recurse for each element
  - **A1_OP_BMEMBER**: Iterate JSON string array, set bits by name lookup
  - **A1_OP_CHOICE**: Read `_choice` key from JSON dict, find matching
    alternative, recurse for `value`
  - **A1_OP_OPENTYPE_OBJSET**: Handle open types (parse `_<name>_choice` and
    `_<name>` fields from the JSON dict)
  - **A1_OP_TYPE_DECORATE / A1_OP_TYPE_DECORATE_EXTERN**: Skip (same as print)
  - For OPTIONAL fields: if JSON value is `null`, leave pointer NULL; otherwise
    allocate and recurse
  - For DEFAULT fields: if JSON value is absent or `null`, apply default (same
    logic as `_asn1_decode`)

- `_asn1_parse_json_top()` — entry point, mirrors `_asn1_decode_top()`:
  ```c
  int _asn1_parse_json_top(const struct asn1_template *t,
                           heim_object_t json, void *data)
  ```
  Calls `memset(data, 0, t->offset)`, then `_asn1_parse_json()`, and on error
  calls `_asn1_free_top()`.

### 2. `lib/asn1/asn1-template.h` — Add declaration

Add declaration for `_asn1_parse_json_top()` alongside the existing
declarations for `_asn1_decode_top`, `_asn1_print_top`, etc.

### 3. `lib/asn1/gen_template.c` — Generate `asn1_parse_<TYPE>()` stubs

After the existing `print_<TYPE>()` stub generation (line ~1688), add:

```c
fprintf(f,
    "\n"
    "int ASN1CALL\n"
    "asn1_parse_%s(const char *jstr, size_t jlen, %s *data)\n"
    "{\n"
    "    heim_object_t j;\n"
    "    heim_error_t e = NULL;\n"
    "    int ret;\n"
    "\n"
    "    if (jlen == 0) jlen = strlen(jstr);\n"
    "    j = heim_json_create_with_bytes(jstr, jlen, 10, 0, &e);\n"
    "    if (!j) { heim_release(e); return EINVAL; }\n"
    "    memset(data, 0, sizeof(*data));\n"
    "    ret = _asn1_parse_json_top(asn1_%s, j, data);\n"
    "    heim_release(j);\n"
    "    return ret;\n"
    "}\n",
    s->gen_name, s->gen_name, dupname);
```

**Function signature**: `int asn1_parse_<TYPE>(const char *json, size_t len, <TYPE> *data)`
- `json` is a NUL-terminated JSON string (or `len` bytes if `len > 0`)
- Returns 0 on success, error code on failure
- On failure, `data` is zeroed (freed by `_asn1_parse_json_top`)

### 4. `lib/asn1/gen.c` — Generate header declaration

After the `print_<TYPE>()` declaration (line ~2088), add:

```c
fprintf(h,
    "%sint    ASN1CALL asn1_parse_%s (const char *, size_t, %s *);\n",
    exp, s->gen_name, s->gen_name);
```

### 5. `lib/asn1/gen_print.c` — Non-template backend stub

Add a `asn1_parse_<TYPE>()` stub that returns ENOTSUP, for the non-template
(codegen) backend:

```c
void
generate_type_parse_stub(const Symbol *s)
{
    fprintf(codefile, "int ASN1CALL\n"
            "asn1_parse_%s(const char *j, size_t l, %s *d)\n"
            "{ return ENOTSUP; }\n\n",
            s->gen_name, s->gen_name);
}
```

And call it from gen.c alongside `generate_type_print_stub()`.

### 6. `lib/asn1/asn1_print.c` — Add JSON-to-DER mode (optional, can defer)

Add a `--from-json` mode that reads JSON from stdin, calls `asn1_parse_<TYPE>()`,
then encodes to DER with `encode_<TYPE>()`.  This enables:
```
asn1_print file.der Certificate | asn1_print --from-json Certificate > roundtrip.der
```

### 7. Tests

Add a round-trip test that for each type:
1. Decodes a DER value
2. Prints to JSON via `print_<TYPE>()`
3. Parses JSON back via `asn1_parse_<TYPE>()`
4. Encodes to DER via `encode_<TYPE>()`
5. Compares original DER with round-tripped DER

This can be added to the existing `check-template.c` or `check-gen.c` tests,
or to `asn1_print.c` as a `--test-json-roundtrip` flag.

## Primitive Type Parsing Details (`_asn1_parse_json_prim`)

For each `enum template_types` value, the JSON-to-C conversion:

| Type | JSON input | C conversion |
|------|-----------|-------------|
| A1T_IMEMBER (enum) | `"name"` or number | Reverse name lookup in enum template, or `heim_number_get_int()` |
| A1T_HEIM_INTEGER | `"hex"` string | `hex_decode()` to build `heim_integer` |
| A1T_INTEGER | number | `heim_number_get_int()` |
| A1T_INTEGER64 | number | `heim_number_get_long()` |
| A1T_UNSIGNED | number | `(unsigned)heim_number_get_int()` |
| A1T_UNSIGNED64 | number | `(uint64_t)heim_number_get_long()` |
| A1T_GENERAL_STRING | `"str"` | `strdup(heim_string_get_utf8())` |
| A1T_OCTET_STRING | `"hex"` | `hex_decode()` → `heim_octet_string` |
| A1T_IA5_STRING | `"str"` | Build `heim_ia5_string` from UTF-8 |
| A1T_PRINTABLE_STRING | `"str"` | Build `heim_printable_string` from UTF-8 |
| A1T_VISIBLE_STRING | `"str"` | `strdup()` |
| A1T_UTF8_STRING | `"str"` | `strdup(heim_string_get_utf8())` |
| A1T_GENERALIZED_TIME | `"2024-..."` | `strptime()` → `time_t` |
| A1T_UTC_TIME | `"2024-..."` | `strptime()` → `time_t` |
| A1T_HEIM_BIT_STRING | `"len:hex"` | Parse length, `hex_decode()` → `heim_bit_string` |
| A1T_BOOLEAN | `true`/`false` | `heim_bool_val()` |
| A1T_OID | `{"oid":"1.2.3",...}` | `der_parse_heim_oid()` on the "oid" string |
| A1T_NULL | `null` | No-op |
| A1T_BMP_STRING | `"str"` | Best-effort or error |
| A1T_UNIVERSAL_STRING | `"str"` | Best-effort or error |
| A1T_TELETEX_STRING | `"str"` | `strdup()` |

## Implementation Order

1. Add `_asn1_parse_json_top()` declaration to `asn1-template.h`
2. Implement `_asn1_parse_json_prim()` and `_asn1_parse_json()` in `template.c`
3. Add `asn1_parse_<TYPE>()` stub generation in `gen_template.c`
4. Add `asn1_parse_<TYPE>()` header declaration in `gen.c`
5. Add `asn1_parse_<TYPE>()` non-template stub in `gen_print.c`
6. Add round-trip test in `asn1_print.c` (`--test-json-roundtrip` flag)
7. Build and test

## Risks and Considerations

- **VIS-encoded strings**: `_asn1_print` uses `rk_strasvis()` to escape strings.
  The parser must reverse this with `rk_strunvis()` or similar.
- **Open types**: The open type handling is complex.  Initial implementation can
  skip open types (return ENOTSUP if encountered) and add support later.
- **BMP/Universal strings**: Print outputs placeholders; parsing these is
  low priority.
- **No ABI changes**: We do NOT modify `struct asn1_type_func`.  All JSON
  parsing logic is self-contained in the new functions.
- **Dependency on heimbase**: `template.c` already includes `<heimbase.h>`.
  The JSON parsing functions use `heim_dict_t`, `heim_array_t`, etc.
