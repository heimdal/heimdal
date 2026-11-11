# Plan: Java ASN.1 Codec Generation from Heimdal's ASN.1 Compiler

Session: https://claude.ai/code/session_01XBEKHRaPVDhuWpqDaBptKt

## Motivation

Heimdal's ASN.1 compiler already parses the complete set of ASN.1 modules
needed for Kerberos, PKIX, CMS, PKINIT, and related protocols.  It already
emits a `.json` metadata file for each compiled module.  By enriching that
JSON and writing an external Java code generator that consumes it, we can
produce high-quality Java DER codecs without maintaining a separate ASN.1
parser or compiler — the single source of truth remains the `.asn1` files
and the Heimdal compiler.

Use cases:

- **Java Kerberos libraries** that need to encode/decode Kerberos protocol
  messages (AS-REQ, TGS-REP, AP-REQ, etc.) without relying on Sun's
  internal `sun.security.krb5` classes.
- **Java PKIX libraries** for certificate parsing, OCSP, CMS, PKINIT.
- **Interop testing** — the same ASN.1 definitions produce both C and Java
  codecs, ensuring wire-compatible behavior.
- **Android / embedded Java** — generated code with no reflection, no
  runtime code generation, minimal dependencies.

## Architecture

### Why an external codegen tool (not a new backend in asn1_compile)

The C code generator in `asn1_compile` is deeply coupled to C-specific
concerns: struct layouts, pointer arithmetic, `{len, *val}` array
representations, `goto`-based cleanup, etc.  Adding Java codegen inside
the C compiler would fight this at every turn.

Instead:

```
  .asn1 files ──> asn1_compile ──> .json (enriched) ──> java-asn1-gen ──> .java files
                      │                                      │
                      │                                      └── reads JSON, emits Java
                      └── existing C codegen (unchanged)
```

The external tool (`java-asn1-gen`) can be written in Python or Java.
Python is a reasonable choice for a code generator: it's already a build
dependency (for `make-proto.pl` equivalent tasks), it handles JSON
natively, and string manipulation for codegen is natural.

### Why not templates / reflection

Java reflection-based DER codecs (annotate fields, walk them at runtime)
work but have significant drawbacks:

- **Performance** — reflection is slow, especially on Android.
- **No ahead-of-time visibility** — you can't see the generated codec
  logic, making debugging painful.
- **Annotation complexity** — ASN.1's tagging, OPTIONAL/DEFAULT, CHOICE,
  and open type semantics are hard to express in annotations alone.

Instead, generate **static descriptor tables** (similar to the C
`--template` backend) that a small hand-written DER runtime walks.
This gives:

- Full type safety at compile time.
- Inspectable generated code (each type gets a `DESCRIPTOR` constant).
- A single, testable DER runtime (~2000 lines) that never changes per
  module.
- Performance close to hand-written encode/decode.

---

## Phase 1: Enrich the JSON Output

The current JSON output (emitted by `gen.c` into `<module>_asn1.json`)
captures most of the type information but is missing several things a
Java backend needs.

### 1.1 What the JSON already has

Each `.json` file is a sequence of concatenated JSON objects (one per
top-level definition), containing:

| Feature | JSON representation |
|---|---|
| Module metadata | `{"module":"NAME","tagging":"explicit","objid":[...]}` |
| Type definitions | `{"name":"T","gen_name":"T","ttype":{...recursive...}}` |
| Tags | `"tagclass":"CONTEXT","tagvalue":0,"tagenv":"EXPLICIT"` |
| SEQUENCE members | `"members":[{"name":"f","optional":true,"type":{...}}]` |
| SEQUENCE OF / SET OF | `"ttype":"SEQUENCE OF","members":[len, *val]` |
| CHOICE variants | `"ttype":"CHOICE","members":[...],"extensible":true` |
| BIT STRING named bits | `"ttype":"BIT STRING","members":[{"gen_name":"flag:1",...}]` |
| ENUMERATED | `"ttype":"INTEGER","ctype":"enum","members":[{"NAME":val}]` |
| Type aliases | `"ttype":"OtherType","alias":true` |
| APPLICATION tags | `"tagclass":"APPLICATION","tagvalue":10` |
| Open types (IOS) | `"opentype":true,"classname":"...","opentypeids":[...]` |
| OID constants | `"type":"OBJECT IDENTIFIER","constant":true,"value":[arcs]` |
| Integer constants | `"type":"INTEGER","constant":true,"value":5` |
| Preserve flag | `"preserve":true` |
| Extensibility | `"extensible":true` |

### 1.2 What needs to be added

**A. DEFAULT values** — The `Member` struct has a `defval` field
(`struct value *`) that is never written to JSON.  Need to emit:

```json
{"name":"cA","optional":true,"defval":{"type":"boolean","value":false}}
{"name":"minimum","optional":true,"defval":{"type":"integer","value":0}}
```

**B. Range / SIZE constraints** — The `Type` struct has a `range` field
(`struct range *` with `min`, `max`) that is never emitted.  Need:

```json
"range":{"min":0,"max":4294967295}
```

This matters for Java: it determines whether a field should be `int`,
`long`, or `BigInteger`, and enables validation.

**C. Import map** — Currently there's only `{"imports":"MODULE"}` with no
detail.  Need:

```json
{"imports":"RFC2459","types":["AlgorithmIdentifier","Certificate",...]}
```

This lets the Java codegen resolve cross-module type references to the
correct Java package.

**D. Flattened OID dotted notation** — The JSON has arc components with
labels, but not the computed dotted form.  Adding it is convenient:

```json
{"name":"id-pkcs1","value":[...arcs...],"dotted":"1.2.840.113549.1.1"}
```

**E. SEQUENCE OF / SET OF cleanup** — Currently these emit C-specific
`{"gen_name":"len",...},{"gen_name":"*val",...}` members.  For
language-neutral JSON, emit the element type directly:

```json
{"ttype":"SEQUENCE OF","element":{"ttype":"HostAddress","alias":true}}
```

(Keep the C-specific form too, or gate it on a flag.)

### 1.3 Implementation

All changes are in `lib/asn1/gen.c`, in the `define_type()` function
(lines ~1190-1713) and `generate_type_jsonfile()`.  The internal data
structures already have all the information; it's just not being
`fprintf(jsonfile, ...)`'d.

Estimated size: ~200-300 lines of additions to `gen.c`.

---

## Phase 2: Java DER Runtime Library

A small, hand-written Java library that provides:

### 2.1 Core DER primitives

```java
package com.heimdal.asn1;

public class DerInputStream {
    // Read a TLV header, return tag + length
    // Decode primitive types: INTEGER, BOOLEAN, OCTET STRING, etc.
    // Handle constructed types: enter/leave SEQUENCE, SET
}

public class DerOutputStream {
    // Write TLV headers
    // Encode primitive types
    // Handle constructed: open/close SEQUENCE, SET
    // DER length computation (two-pass or buffered)
}
```

### 2.2 Type descriptor framework

```java
public sealed interface TypeDescriptor {
    record Primitive(int tag, PrimitiveType type) implements TypeDescriptor {}
    record Sequence(String javaClass, FieldDescriptor[] fields,
                    boolean extensible) implements TypeDescriptor {}
    record SequenceOf(TypeDescriptor element) implements TypeDescriptor {}
    record SetOf(TypeDescriptor element) implements TypeDescriptor {}
    record Choice(String javaClass, VariantDescriptor[] variants,
                  boolean extensible) implements TypeDescriptor {}
    record Tagged(TagClass tagClass, int tagValue, TagEnv env,
                  TypeDescriptor inner) implements TypeDescriptor {}
    record TypeRef(String typeName,
                   Supplier<TypeDescriptor> resolved) implements TypeDescriptor {}
    record BitStringNamed(String javaClass,
                          String[] bitNames) implements TypeDescriptor {}
    record Enumerated(String javaClass,
                      Map<String,Integer> values) implements TypeDescriptor {}
    // ... OpenType, Null, OID
}
```

### 2.3 Generic codec engine

```java
public class DerCodec {
    public static <T> T decode(TypeDescriptor desc, byte[] der) { ... }
    public static <T> byte[] encode(TypeDescriptor desc, T value) { ... }
}
```

This walks the descriptor tree, dispatching to the appropriate
encode/decode logic for each node.  OPTIONAL fields are handled by
peeking at the next tag.  DEFAULT fields compare against the default
value on encode (omit if equal) and substitute on decode (if absent).

### 2.4 Open type support

For types like `AlgorithmIdentifier` where `parameters` is an open type
keyed by the `algorithm` OID:

```java
// Generated
public class AlgorithmIdentifier {
    public OID algorithm;
    public Object parameters;  // decoded based on algorithm

    static final OpenTypeDescriptor OPEN_TYPE = OpenTypeDescriptor.builder()
        .discriminant("algorithm")
        .openField("parameters")
        .register(OIDs.id_dsa_with_sha1, NullType.DESCRIPTOR)
        .register(OIDs.id_pkcs1_sha256WithRSAEncryption, NullType.DESCRIPTOR)
        .build();
}
```

The runtime resolves the OID at decode time and uses the registered
descriptor.  Unknown OIDs produce a raw `byte[]` (the undecoded
content).

### 2.5 Estimated size

~2000-3000 lines of Java.  No external dependencies beyond the JDK.

Minimum Java version: **Java 17** (sealed interfaces for CHOICE,
records for value types, modern switch expressions).  If Java 11
compatibility is required, use abstract classes instead of sealed
interfaces — more boilerplate but functionally equivalent.

---

## Phase 3: Java Code Generator (`java-asn1-gen`)

A standalone tool that reads the enriched JSON and emits Java source
files.

### 3.1 Input

All `*_asn1.json` files for the modules to generate.  The tool needs
to read multiple modules simultaneously to resolve cross-module type
references (e.g., `krb5.asn1` references types from `rfc2459.asn1`).

### 3.2 Processing pipeline

```
1. Parse all JSON files into an internal type model
2. Build a global symbol table: type name -> (module, definition)
3. Resolve all type aliases to their defining module
4. Determine Java package for each ASN.1 module
5. For each type, emit a Java class/enum/interface
6. Emit module-level constants class (OIDs, integer constants)
7. Emit module-level codec class (optional convenience wrappers)
```

### 3.3 Type mapping

| ASN.1 construct | Java output |
|---|---|
| SEQUENCE | Class with public fields + `static final TypeDescriptor DESCRIPTOR` |
| SEQUENCE OF | `java.util.List<E>` (field type); element descriptor in parent |
| SET OF | `java.util.Set<E>` or `List<E>` (DER requires sorted encoding) |
| CHOICE | Sealed interface with record variants |
| ENUMERATED | Java `enum` with `int value` field |
| INTEGER (enum-like) | Java `enum` with `int value` field |
| INTEGER (small, ranged) | `int` or `long` depending on range |
| INTEGER (unbounded) | `java.math.BigInteger` |
| BOOLEAN | `boolean` |
| OCTET STRING | `byte[]` |
| BIT STRING (unnamed) | `byte[]` + `int unusedBits`, or `java.util.BitSet` |
| BIT STRING (named bits) | Class with `boolean` fields |
| All string types | `String` |
| GeneralizedTime, UTCTime | `java.time.Instant` |
| OBJECT IDENTIFIER | `int[]` or dedicated `OID` class |
| NULL | `Void` or singleton |
| OPTIONAL field | `@Nullable` (or `Optional<T>` — TBD) |
| DEFAULT field | Nullable; default value in descriptor |
| APPLICATION-tagged alias | Subclass or type alias with tag wrapper |

### 3.4 Package structure

One Java package per ASN.1 module:

```
com.heimdal.asn1.krb5/
    PrincipalName.java
    KDCOptions.java
    AS_REQ.java
    ...
    Krb5Constants.java      // OID + integer constants
com.heimdal.asn1.rfc2459/
    Certificate.java
    AlgorithmIdentifier.java
    ...
com.heimdal.asn1.cms/
    SignedData.java
    ...
```

### 3.5 CHOICE codegen example

For the Kerberos `PA-DATA` padata-value, which is an OCTET STRING
(not a CHOICE), but for a true CHOICE like `PrincipalNameAttrSrc`:

```java
// Generated from ASN.1: PrincipalNameAttrSrc ::= CHOICE { ...  }
public sealed interface PrincipalNameAttrSrc {
    record Enc(EncryptedData value) implements PrincipalNameAttrSrc {}
    record Unsigned(Ticket value) implements PrincipalNameAttrSrc {}

    TypeDescriptor DESCRIPTOR = TypeDescriptor.choice(
        PrincipalNameAttrSrc.class,
        variant("enc", 0, CONTEXT, EXPLICIT, EncryptedData.DESCRIPTOR, Enc::new),
        variant("unsigned", 1, CONTEXT, EXPLICIT, Ticket.DESCRIPTOR, Unsigned::new)
    );
}
```

### 3.6 SEQUENCE codegen example

```java
// Generated from ASN.1: PrincipalName ::= SEQUENCE { ... }
public class PrincipalName {
    public NameType nameType;        // [0] NAME-TYPE
    public List<String> nameString;  // [1] SEQUENCE OF GeneralString

    public static final TypeDescriptor DESCRIPTOR = TypeDescriptor.sequence(
        PrincipalName.class,
        field("nameType", 0, CONTEXT, EXPLICIT, NameType.DESCRIPTOR,
              PrincipalName::getNameType, PrincipalName::setNameType),
        field("nameString", 1, CONTEXT, EXPLICIT,
              sequenceOf(generalString()),
              PrincipalName::getNameString, PrincipalName::setNameString)
    );

    // Generated getters/setters for descriptor field access
    // (or use MethodHandles / VarHandles for zero-overhead access)
}
```

### 3.7 Estimated size

~1500-2000 lines of Python (or ~2500-3000 lines if written in Java).

---

## Phase 4: Build Integration

### 4.1 Makefile integration

The JSON files are already produced as a side effect of `asn1_compile`.
The Java codegen step would be an additional make target:

```makefile
# In lib/asn1/Makefile.am or a new java/Makefile.am
JAVA_ASN1_GEN = $(top_srcdir)/lib/asn1/java-asn1-gen.py

java-krb5-sources: krb5_asn1.json rfc2459_asn1.json
	$(PYTHON) $(JAVA_ASN1_GEN) \
	    --module krb5_asn1.json --package com.heimdal.asn1.krb5 \
	    --module rfc2459_asn1.json --package com.heimdal.asn1.rfc2459 \
	    --output-dir $(builddir)/java-gen
```

### 4.2 Java build

The generated Java sources would be built with Maven or Gradle.  This
could be a separate `java/` directory at the top level, or even a
separate repository that consumes the JSON files as build inputs.

### 4.3 Testing

- **Round-trip tests**: Encode a Java object to DER, decode it back,
  verify equality.
- **Cross-language tests**: Encode in C (using existing Heimdal), decode
  in Java (and vice versa).  The existing test vectors in
  `tests/kdc/kdc-tester*.json` and the DER blobs from `make check` can
  serve as golden files.
- **Conformance tests**: Use the X.690 examples (`x690sample.asn1`)
  which have known DER encodings.
- **Fuzz testing**: Feed random DER to the Java decoder, verify it
  either decodes correctly or throws a clean exception (no crashes,
  no resource leaks).

---

## Phase 5 (Optional): Bidirectional JSON Codec

If the PLAN-revamp.md JER (JSON Encoding Rules) work lands first, the
Java codegen could also emit JSON codec descriptors, enabling
Java ↔ JSON ↔ DER round-tripping.  This is orthogonal to the DER codec
work and can be added later.

---

## Scope of ASN.1 Modules

The following modules would be candidates for Java codegen.  Not all
are needed for a minimal Kerberos client; priority ordering:

| Priority | Module | Types | Use case |
|---|---|---|---|
| **P0** | `krb5.asn1` | ~110 | Kerberos protocol messages |
| **P0** | `rfc2459.asn1` | ~200+ | X.509 certs (needed by krb5 for PKINIT, name types) |
| **P1** | `cms.asn1` | ~30 | CMS/PKCS#7 (needed by PKINIT) |
| **P1** | `pkinit.asn1` | ~25 | PKINIT extension |
| **P2** | `spnego.asn1` | ~8 | SPNEGO negotiation |
| **P2** | `hdb.asn1` | ~40 | KDC database (for Java admin tools) |
| **P3** | `pkcs8.asn1` | ~3 | Private key wrapping |
| **P3** | `pkcs12.asn1` | ~15 | Key exchange format |
| **P3** | `ocsp.asn1` | ~15 | Certificate revocation |
| **P3** | `crmf.asn1` | ~15 | Certificate requests |
| **P3** | Others | ~30 | pkcs9, pkcs10, kx509, rfc4108, digest, pku2u |

---

## Open Design Decisions

1. **Minimum Java version**: Java 17 (sealed interfaces, records) vs
   Java 11 (wider compatibility, more boilerplate).  Recommendation:
   **Java 17** — it's the current LTS and the language features
   materially simplify CHOICE and value type codegen.

2. **OPTIONAL representation**: `@Nullable` fields vs `Optional<T>`.
   `@Nullable` is simpler and avoids Optional's overhead for primitive
   wrappers.  Recommendation: **nullable fields** with
   `@javax.annotation.Nullable` annotation.

3. **Field access for descriptors**: The descriptor-based codec needs to
   get/set fields on generated objects.  Options:
   - Public fields (simplest, fastest)
   - Generated getters/setters (more Java-idiomatic)
   - `MethodHandle` / `VarHandle` (zero overhead, complex setup)
   Recommendation: **public fields** — these are data transfer objects,
   not encapsulated domain objects.  Mirror the C approach.

4. **Codegen tool language**: Python vs Java.  Python is already a build
   dependency and is natural for string-heavy codegen.  Java would
   allow the codegen to be a Maven plugin.  Recommendation: **Python**
   for initial implementation; can be rewritten later if needed.

5. **Repository location**: In-tree (`lib/asn1/java/`) vs separate repo.
   Recommendation: **in-tree** initially — keeps the JSON schema and
   consumer in sync.  Can be extracted later once the JSON format
   stabilizes.

6. **SET OF encoding**: DER requires SET OF elements to be sorted by
   their encoded form.  Use `List<T>` internally, sort during encode.
   This is a runtime concern, not a codegen concern.

7. **Immutability**: Generated classes could be mutable (like C structs)
   or immutable (builder pattern).  Recommendation: **mutable** — matches
   the C approach, simpler codegen, and decode-then-modify is a common
   pattern in Kerberos code.
