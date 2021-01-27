Bringing the power of X.682 (ASN.1 Information Object System) to Heimdal
========================================================================

X.681 is an ITU-T standard in the X.680 series (ASN.1) that is incredibly
useful and would be fantastic to implement in Heimdal.

This README will cover some ideas for implementation and why we should want
this.  This is also covered extensively in RFC 6025, in section 2.1.3.

RFC 6025 does an excellent job of elucidating X.681, which otherwise most
readers unfamiliar with it will no doubt find inscrutable.

https://www.itu.int/rec/T-REC-X.681-201508-I/en


Introduction
============

The reader should already be familiar with ASN.1, which anyways is a set of two
things:

 - an abstract syntax for specifying schemas for data interchange

 - a set of encoding rules

A very common thing to see in projects that use ASN.1, as well as projects that
use alternatives to ASN.1, is a pattern known as the "typed hole" or "open
type".

The ASN.1 Information Object System (X.681) is all about automating the
otherwise very annoying task of dealing with "typed holes" / "open types".


Typed Holes / Open Types
========================

A typed hole or open type is a data structure with a form like:

```
    { type_id, bytes_encoding_a_value_of_a_type_identified_by_type_id }
```

I.e., an opaque datum and an identifier of what kind of datum that is.  This
happens because the structure with the typed hole is used in contexts where it
can't know all possible things that can go in it.  In many cases we do know
what all possible things are that can go in a typed hole, but many years ago
didn't, say, or anyways, had a reason to use a typed hole.

These are used not only in protocols that use ASN.1, but in many protocols that
use alternative syntaxes and encodings.

In ASN.1 these generally look like:

```
    TypedHole ::= SEQUENCE { typeId INTEGER, hole OCTET STRING }
```

or

```
    TypedHole ::= SEQUENCE {
        typeId OBJECT IDENTIFIER,
        opaque ANY DEFINED BY typeID
    }
```

or

```
    TypedHole ::= SEQUENCE {
        typeId OBJECT IDENTIFIER,
        opaque ANY -- DEFINED BY typeID
    }
```

or any number of variations.  (Note: the `ANY` variations are no longer
conformant to X.680 (the base ASN.1 specification).)

The pattern is `{ id, hole }` where the `hole` is ultimately an opaque sequence
of bytes whose content's schema is identified by the `id` in the same data
structure.

Sometimes the "hole" is an `OCTET STRING`, sometimes it's a `BIT STRING`,
sometimes it's an `ANY` or `ANY DEFINED BY`.

An example from PKIX:

```
Extension ::= SEQUENCE {
  extnID          OBJECT IDENTIFIER, -- <- type ID
  critical        BOOLEAN OPTIONAL,
  extnValue       OCTET STRING,      -- <- hole
}
```

which shows that typed holes don't always have just three fields, and the type
identifier isn't always an integer.

Now, Heimdal's ASN.1 compiler generates the obvious C data structure for PKIX's
`Extension` type:

```
    typedef struct Extension {
      heim_oid extnID;
      int *critical;
      heim_octet_string extnValue;
    } Extension;
```

and applications using this compiler have to inspect the `extnID` field,
comparing it to any number of OIDs, to determine the type of `extnValue`, then
must call `decode_ThatType()` to decode whatever that octet string has.

This is very inconvenient.

Compare this to the handling of discriminated unions (what ASN.1 calls a
`CHOICE`):

```
    /*
     * ASN.1 definition:
     *
     *  DistributionPointName ::= CHOICE {
     *    fullName                  [0] IMPLICIT SEQUENCE OF GeneralName,
     *    nameRelativeToCRLIssuer   [1] RelativeDistinguishedName,
     *  }
    */

    /* C equivalent */
    typedef struct DistributionPointName {
      enum DistributionPointName_enum {
        choice_DistributionPointName_fullName = 1,
        choice_DistributionPointName_nameRelativeToCRLIssuer
      } element;
      union {
        struct DistributionPointName_fullName {
          unsigned int len;
          GeneralName *val;
        } fullName;
        RelativeDistinguishedName nameRelativeToCRLIssuer;
      } u;
    } DistributionPointName;
```

The ASN.1 encoding on the wire of a `CHOICE` value, almost no matter the
encoding rules, looks... remarkably like the encoding of a typed hole.  Though
generally the alternatives of a discriminated union have to all be encoded with
the same encoding rules, whereas with typed holes the encoded data could
conceivably be encoded in radically different encoding rules than the structure
containing it in a typed hole.

In fact, extensible `CHOICE`s are handled by our compiler as a discriminated
union one of whose alternatives is a typed hole when the `CHOICE` is
extensible:

```
    typedef struct DigestRepInner {
      enum DigestRepInner_enum {
        choice_DigestRepInner_asn1_ellipsis = 0, /* <--- unknown CHOICE arm */
        choice_DigestRepInner_error,
        choice_DigestRepInner_initReply,
        choice_DigestRepInner_response,
        choice_DigestRepInner_ntlmInitReply,
        choice_DigestRepInner_ntlmResponse,
        choice_DigestRepInner_supportedMechs
        /* ... */
      } element;
      union {
        DigestError error;
        DigestInitReply initReply;
        DigestResponse response;
        NTLMInitReply ntlmInitReply;
        NTLMResponse ntlmResponse;
        DigestTypes supportedMechs;
        heim_octet_string asn1_ellipsis; /* <--- unknown CHOICE arm */
      } u;
    } DigestRepInner;
```

The critical thing to understand is that our compiler automatically decodes
(and encodes) `CHOICE`s' alternatives, but it does NOT do that for typed holes
because it knows nothing about them.

It would be nice if we could treat *all* typed holes like `CHOICE`s whenever
the compiler knows the alternatives!

And that's exactly what the ASN.1 IOS system makes possible.  With ASN.1 IOS
support, our compiler could automatically decode all the `Certificate`
extensions, and all the distinguished name extensions it knows about.

There is a fair bit of code in `lib/hx509/` that deals with encoding and
decoding things in typed holes where the compiler could just handle that
automatically for us, allowing us to delete a lot of code.

Even more importantly, if we ever add support for visual encoding rules of
ASN.1, such as JSON Encoding Rules (JER) [X.697] or Generic String Encoding
Rules (GSER) [RFC2641], we could have a utility program to automatically
display or compile DER (and other encodings) of certifcates and many other
interesting data structures.


ASN.1 IOS
=========

The ASN.1 IOS is additional syntax that allows ASN.1 module authors to express
all the details about typed holes that ASN.1 compilers need to make developers'
lives much easier.

RFC5912 has lots of examples, such as this `CLASS` corresponding to the
`Extension` type from PKIX:

```
  EXTENSION ::= CLASS {
      &id  OBJECT IDENTIFIER UNIQUE,
      &ExtnType,
      &Critical    BOOLEAN DEFAULT {TRUE | FALSE }
  } WITH SYNTAX {
      SYNTAX &ExtnType IDENTIFIED BY &id
      [CRITICALITY &Critical]
  }

  Extensions{EXTENSION:ExtensionSet} ::=
      SEQUENCE SIZE (1..MAX) OF Extension{{ExtensionSet}}

  Extension{EXTENSION:ExtensionSet} ::= SEQUENCE {
      extnID      EXTENSION.&id({ExtensionSet}),
      critical    BOOLEAN
  --                     (EXTENSION.&Critical({ExtensionSet}{@extnID}))
                       DEFAULT FALSE,
      extnValue   OCTET STRING (CONTAINING
                  EXTENSION.&ExtnType({ExtensionSet}{@extnID}))
                  --  contains the DER encoding of the ASN.1 value
                  --  corresponding to the extension type identified
                  --  by extnID
  }
```

and these uses of it in RFC5280 (PKIX base):

```
   ext-AuthorityKeyIdentifier EXTENSION ::= { SYNTAX
       AuthorityKeyIdentifier IDENTIFIED BY
       id-ce-authorityKeyIdentifier }
   id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
   ...

   CertExtensions EXTENSION ::= {
           ext-AuthorityKeyIdentifier | ext-SubjectKeyIdentifier |
           ext-KeyUsage | ext-PrivateKeyUsagePeriod |
           ext-CertificatePolicies | ext-PolicyMappings |
           ext-SubjectAltName | ext-IssuerAltName |
           ext-SubjectDirectoryAttributes |
           ext-BasicConstraints | ext-NameConstraints |
           ext-PolicyConstraints | ext-ExtKeyUsage |
           ext-CRLDistributionPoints | ext-InhibitAnyPolicy |
           ext-FreshestCRL | ext-AuthorityInfoAccess |
           ext-SubjectInfoAccessSyntax, ... }
   ...

   Certificate  ::=  SIGNED{TBSCertificate}

   TBSCertificate  ::=  SEQUENCE  {
       version         [0]  Version DEFAULT v1,
       serialNumber         CertificateSerialNumber,
       signature            AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                                 {SignatureAlgorithms}},
       issuer               Name,
       validity             Validity,
       subject              Name,
       subjectPublicKeyInfo SubjectPublicKeyInfo,
       ... ,
       [[2:               -- If present, version MUST be v2
       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
       ]],
       [[3:               -- If present, version MUST be v3 --
       extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
       ]], ... }
```

Notice that the `extensions` field of `TBSCertificate` is of type `Extensions`
parametrized by the `CertExtensions` IOS object set.

This allows the compiler to know that if any of the OIDs listed in the
`CertExtensions` object set appear as the actual value of the `extnID` member
of an `Extension` value, then the `extnValue` member of the same `Extension`
value must be an instance of the type associated with that OID.  For example,
an `Extension` with `extnID == id-ce-authorityKeyIdentifier` must have an
`extnValue` of type `AuthorityKeyIdentifier`.


Implementation Thoughts
=======================

 - The ASN.1 IOS is fairly large and non-trivial.  Perhaps we can just bake in
   a few useful IOS classes without adding support for defining arbitrary
   classes.

   For dealing with PKIX, the bare minimum of IOS classes we should want are:

    - ATTRIBUTE (used for DN attributes in PKIX base)
    - EXTENSION (used for certificate attributes in PKIX base)

   Then we can implement support for just declarations of information objects
   and information object sets in `lib/asn1parse.y`, which is probably not a
   very big deal.

   Internally we can have a function for creating a class.

 - We'll really want to do this mainly for the template compiler and begin
   abandoning the original compiler -- hacking on two compilers is difficult,
   and the template compiler is superior just on account of emitted code size
   scaling as `O(N)` instead of `O(M * N)` where `M` is the number of encoding
   rules supported and `N` is the number of types in an ASN.1 module (or all
   modules).

 - Also, to make the transition to using IOS in-tree, we'll want to add fields
   to the C structures generated by the compiler today, that way code that
   hasn't been updated to use the automatic encoding/decoding can still work.

   Thus `Extension` should compile to:

```
    typedef struct Extension {
      heim_oid extnID;
      int *critical;
      heim_octet_string extnValue;
      enum Extension_iosnum {
        Extension_iosnumunknown = 0, /* when the extnID is unrecognized */
        Extension_iosnum_ext_AuthorityKeyIdentifier = 1,
        Extension_iosnum_ext_ext-SubjectKeyIdentifier = 2,
        ...
      } _ios_element;
      union {
        heim_octet_string *_value;
        authorityKeyIdentifier AuthorityKeyIdentifier;
        subjectKeyIdentifier SubjectKeyIdentifier;
        ...
      } _ios_u;
    } Extension;
```

   If a caller to `encode_Certificate()` passes a certificate object with
   extensions with `_ioselement == Extension_iosnumunknown`, then the encoder
   should use the `extnID` and `extnValue` fields, otherwise it should use the
   `_ioselement` and `_iosu` fields.  (In both cases, the `critical` field
   should get used.)

 - We'll need to reduce the number of bits used to encode tag values in the
   templates.  Currently we use 20 bits, but that's far too many.  We can
   almost certainly get away with using only 10 bits for tags.  This will allow
   us to have more opcodes, which we'll need more of in order to handle typed
   holes described by IOS classes and information object sets.
