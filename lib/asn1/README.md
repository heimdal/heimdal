# Heimdal's ASN.1 Compiler

This is a new README, and it's not very rich in contents yet.  Be sure to check
out the [README on the template backend](/lib/asn1/README-template.md) and the [README
on automatic open type decoding via X.681/X.682/X.683
annotations](/lib/asn1/README-X681.md).

## Table of Contents

 1. [Introduction](#Introduction)
 2. [ASN.1 Support in Heimdal](#asn1-support-in-heimdal)
 3. [News](#News)
 4. [Features](#Features)
 5. [Limitations](#Limitations)
 6. [Compiler Usage](#Compiler-usage)
 7. [Implementation](#implementation)
 8. [Moving From C](#moving-from-c)

## Introduction

ASN.1 is a... some would say baroque, perhaps obsolete, archaic even, "syntax"
for expressing data type schemas, and also a set of "encoding rules" (ERs) that
specify many ways to encode values of those types for interchange.

Some ERs are binary, others are textual.  Some binary ERs are tag-length-value
(TLV), others have no need for tagging.  Some of the ERs are roundly and
rightly disliked, but then there are XER (XML Encoding Rules) and JER (JSON
Encoding Rules) that really illustrate how the syntax and the encoding rules
really are separate and distinct things.

ASN.1 is a wheel that everyone loves to reinvent, and often badly.  It's worth
knowing a bit about it before reinventing this wheel badly yet again.

It's also worth pondering that there appears to be ways to map most data
exchange metaschemas and schemas onto others, and therefore too, transliterate
most encodings onto others.

First, an example of the syntax:

```ASN.1
-- This is what a certificate looks like (as in TLS server certificates, or
-- "SSL certs):
Certificate  ::=  SEQUENCE  {
     tbsCertificate       TBSCertificate,
     signatureAlgorithm   AlgorithmIdentifier,
     signatureValue       BIT STRING
}

-- The main body of a certificate is here though:
TBSCertificate  ::=  SEQUENCE  {
     version         [0]  Version DEFAULT 1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
     issuerUniqueID  [1]  IMPLICIT BIT STRING OPTIONAL,
     subjectUniqueID [2]  IMPLICIT BIT STRING OPTIONAL,
     extensions      [3]  EXPLICIT Extensions OPTIONAL
}
```

Here we see something akin to a "structure" or "record" with various named
fields of various types.  Some of these are optional, which means they can have
no value given in encodings.  One is defaulted, which means that if no values
is given in encodings then the default value is intended.

Those `[0]` things are called tags and are decidedly obsolete, along with all
"tag-length-value" (TLV) or "self-describing" encoding rules.  Tags appear as
lexical tokens in ASN.1 only because a) in the early 80s TLV encodings were
thought fantastic, and b) automatic tagging wasn't invented and implemented
until it was too late.  New ASN.1 modules should never need to have those tags
appear in the syntax.

ASN.1 has a lot of competition, and may even be obsolete.  Obsolete
technologies take decades to die out because of the need to interoperate with
the installed base.  So even if ASN.1 is obsolete, we find ourselves needing to
implement a large subset of it in order to implement certain important network
protocols.

Encoding rules?  There are many:

 - JSON Encoding Rules (JER) ([X.697](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.697))

   Use JSON instead of some binary scheme like DER (see below).

 - XML Encoding Rules (XER) ([X.693](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.693))

 - Generic String Encoding Rules (GSER) ([RFC2641](https://tools.ietf.org/html/rfc2641))

 - Basic, Distinguished, and Canonical Encoding Rules (BER, DER, CER) ([X.690](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.690)

   These are the dreaded tag-length-value encoding rules.  They are redundant,
   wasteful, and inefficient in spite of being non-textual (i.e., binary)!

   The descriptor "tag-length-value" is due to all values being encoded as some
   bytes for a "tag", then some bytes for the length of the encoded value, then
   the encoded value itself.  The body of a structured type (e.g.,
   `Certificate`) is itself a concatenation of the TLV encodings of the fields
   of that structured type, in order.

   DER and CER are alternative canonical forms of BER.

 - Packed Encoding Rules (PER) ([X.691](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.691)) and Octet Encoding Rules (OER) ([X.696](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.696))

   These are a lot like eXternal Data Representation
   ([XDR](https://tools.ietf.org/html/rfc4506.html)), but with 1-octet
   alignment instead of 4-octet alignment.

There is also a meta encoding rule system, the Encoding Control Notation (ECN)
([X.692](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.692))
intended to be able to express all sorts of kinds of encodings.

Heimdal currently only supports DER for encoding, and DER and BER for decoding,
but soon may support JER as well, and can print values as JSON, though not
compliant with JER.

The syntax itself is specified by
[X.680](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.680),
with extensions via
[X.681](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.681),
[X.682](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.682),
and
[X.683](https://www.itu.int/rec/T-REC-X/recommendation.asp?lang=en&parent=T-REC-X.683),.

## ASN.1 Support in Heimdal

Heimdal contains an implementation of:

 - ASN.1
 - PKIX
 - Kerberos
 - misc. Heimdal-specific protocols related to PKIX and Kerberos, such as:

    - Online certification authority protocols
    - Kerberos KDC replication protocols
    - Kerberos administration protocols

PKIX and Kerberos both require ASN.1 and DER support.

For historical reasons many ASN.1-using projects have used hand-rolled codecs
that have proven difficult to implement, maintain, and extend, and, of course,
buggy.  Heimdal has its own ASN.1 module compiler and library in order to avoid
the pitfalls of hand-rolled codecs, and to satisfy Heimdal's internal needs.

There are other ASN.1 compilers and libraries out there, of course, but it
would prove difficult to switch compilers as generally ASN.1 compilers lack
sufficient control over generated types and APIs for programming languages.

Heimdal's ASN.1 compiler supports a large subset of X.680, X.681, X.682, and
X.683, as well as a large subset of X.690, with an architecture that should
make it easy to add support for encoding rules other than X.690.

## Features

 - Most of X.680 is supported.

 - Most of X.690 is supported for decoding, with only DER supported for
   encoding.

 - We have an `asn1_print` program that can decode DER from any exported types
   from any ASN.1 modules committed in Heimdal:

   ```bash
   $ ./asn1_print ek.crt Certificate |
     jq '.tbsCertificate.extensions[3]._open_type[]._open_type'
   ```

   ```JSON
   [
     {
       "_type": "TPMSpecification",
       "family": "2.0",
       "level": "0",
       "revision": "138"
     }
   ]
   [
     {
       "_type": "TPMSecurityAssertions",
       "version": "0",
       "fieldUpgradable": "1",
       "ekGenerationType": "655617",
       "ekGenerationLocation": "655616",
       "ekCertificateGenerationLocation": "655616",
       "ccInfo": {
         "_type": "CommonCriteriaMeasures",
         "version": "3.1",
         "assurancelevel": "4",
         "evaluationStatus": "2",
         "plus": "1",
         "strengthOfFunction": null,
         "profileOid": null,
         "profileUri": null,
         "targetOid": null,
         "targetUri": null
       },
       "fipsLevel": {
         "_type": "FIPSLevel",
         "version": "140-2",
         "level": "2",
         "plus": "0"
       },
       "iso9000Certified": "0",
       "iso9000Uri": null
     }
   ]
   ```

 - Unconstrained integer types have a large integer representation in C that is
   not terribly useful in common cases.  Range constraints on integer types
   cause the compiler to use `int32_t`, `int64_t`, `uint32_t`, and/or
   `uint64_t`.

 - The Heimdal ASN.1 compiler currently handles a large subset of X.680, and
   (in a branch) a small subset of X.681, X.682, and X.683, which manifests as
   automatic handling of all open types contained in `SET`/`SEQUENCE` types
   that are parameterized with information object sets.  This allows all open
   types in PKIX certificates, for example, to get decoded automatically no
   matter how deeply nested.  We use a TCG EK certificate that has eight
   certificate extensions, including subject alternative names and subject
   directory attributes where the attribute values are not string types, and
   all of these things get decoded automatically.

 - The template backend dedups templates to save space.  This is an O(N^2) kind
   of feature that we need to make optional, but it works.  (When we implement
   JER this will have the side-effect of printing the wrong type names in some
   cases because two or more types have the same templates and get deduped.)

...

## Limitations

 - `asn1_print`'s JSON support is not X.697 (JER) compatible.

 - Control over C types generated is very limited, mainly only for integer
   types.

 - When using the template backend, `SET { .. }` types are currently not sorted
   by tag as they should be, but if the module author sorts them by hand then
   DER will be produced.

 - `BMPString` is not supported.

 - IA5String is not properly supported -- it's essentially treated as a
   `UTF8String` with a different tag.  This is true of all the string types.

 - Only types can be imported at this time.  Without some rototilling we likely
   will not be able to import anything other than types, values, and object
   sets.

 - Only simple value syntax is supported.  Structured value syntax is not
   supported.

 - ...

## Compiler Usage

See the manual page `asn1_compile.1`:

```
ASN1_COMPILE(1)       HEIMDAL General Commands Manual          ASN1_COMPILE(1)

NAME
     asn1_compile — compile ASN.1 modules

SYNOPSIS
     asn1_compile [--template] [--prefix-enum] [--enum-prefix=PREFIX]
                  [--encode-rfc1510-bit-string] [--decode-dce-ber]
                  [--support-ber] [--preserve-binary=TYPE-NAME]
                  [--sequence=TYPE-NAME] [--one-code-file] [--gen-name=NAME]
                  [--option-file=FILE] [--original-order] [--no-parse-units]
                  [--type-file=C-HEADER-FILE] [--version] [--help]
                  [FILE.asn1 [NAME]]

DESCRIPTION
     asn1_compile Compiles an ASN.1 module into C source code and header
     files.

     Options supported:

     --template
             Use the “template” backend instead of the “codegen” backend
             (which is the default backend).  The template backend generates
             “templates” which are akin to bytecode, and which are interpreted
             at run-time.  The codegen backend generates C code for all func‐
             tions directly, with no template interpretation.  The template
             backend scales better than the codegen backend because as we add
             support for more encoding rules the templates stay mostly the
             same, thus scaling linearly with size of module.  Whereas the
             codegen backend scales linear with the product of module size and
             number of encoding rules supported.  More importantly, currently
             only the template backend supports automatic decoding of open
             types via X.681/X.682/X.683 annotations.

     --prefix-enum
             This option should be removed because ENUMERATED types should
             always have their labels prefixed.

     --enum-prefix=PREFIX
             This option should be removed because ENUMERATED types should
             always have their labels prefixed.

     --encode-rfc1510-bit-string
             Use RFC1510, non-standard handling of “BIT STRING” types.

     --decode-dce-ber
     --support-ber

     --preserve-binary=TYPE-NAME
             Generate ‘_save’ fields in structs to preserve the original
             encoding of some sub-value.  This is useful for cryptographic
             applications to avoid having to re-encode values to check signa‐
             tures, etc.

     --sequence=TYPE-NAME
             Generate add/remove functions for ‘SET OF’ and ‘SEQUENCE OF’
             types.

     --one-code-file
             Generate a single source code file.  Otherwise a separate code
             file will be generated for every type.

     --gen-name=NAME
             Use NAME to form the names of the files generated.

     --option-file=FILE
             Take additional command-line options from FILE.

     --original-order
             Attempt to preserve the original order of type definition in the
             ASN.1 module.  By default the compiler generates types in a topo‐
             logical sort order.

     --no-parse-units
             Do not generate to-int / from-int functions for enumeration
             types.

     --type-file=C-HEADER-FILE
             Generate an include of the named header file that might be needed
             for common type defintions.

     --version

     --help

HEIMDAL                        February 22, 2021                       HEIMDAL

```

## Implementation

...

## Futures

 - Add JER support so we can convert between JER and DER?

 - Add XDR support?

 - Add OER support?

 - Add NDR support?

 - Perhaps third parties will contribute more control over generate types?

## Moving From C

 - Generate and output a JSON representation of the compiled ASN.1 module.

 - Code codegen/templategen backends in jq or Haskell or whatever.

 - Code template interpreters in some host language.

 - Eventually rewrite the compiler itself in Rust or whatever.
