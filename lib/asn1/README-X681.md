#Bringing the Magical Power of X.681 (ASN.1 Information Object System) to Heimdal

##Table of Contents

 - [Introduction](#Introduction)
 - [Typed Holes / Open Types](#typed-holes--open-types)
 - [ASN.1 IOS, Constraint, and Parameterization](#asn1-ios-constraint-and-parameterization)
    - [IOS Crash Course](#ios-crash-course)
 - [Implementation Thoughts](#implementation-thoughts)

##Introduction

The base of ASN.1 is specified by X.680, an ITU-T standard.

Various extensions are specified in other X.680 series documents:

 - X.681: Information Object specification
 - X.682: Constraint specification
 - X.683: Parameterization of ASN.1 specifications

While X.680 is essential for implementing many Internet (and other) protocols,
implementing a subset of X.681, X.682, and X.683, can enable some magical
features.  These magical features are generally not the focus of those ITU-T
specifications nor of many RFCs that make use of them.

The intent of X.681, X.682, and X.683 is to add ways to formally express
constraints that would otherwise require natural language to express.  But give
a compiler more formally-expressed constraints and it can do more labor-saving
than it could otherwise.

This README will cover some ideas for what this magic will be, and
implementation of it.

RFC 6025 does an excellent job of elucidating X.681, which otherwise most
readers unfamiliar with it will no doubt find inscrutable.

The magic that we're after is simply the *automatic and recursive handling of
open types by the Heimdal ASN.1 compiler*.

Combined with future support for the ASN.1 JSON Encoding Rules (JER) [X.697],
the automatic handling of open types should allow us to trivially implement a
command-line tool that can parse any DER or JER (JSON) encoding of any value
whose type is known and compiled, and which could transcode to the other
encoding rules.  I.e., dump DER to JSON, and parse JSON to output DER.

Combined with transcoders for JSON/CBOR and other binary-JSON formats, we could
support those encodings too.

We especially want this for PKIX, and more than anything for certificates, as
the TBSCertificate type is full of open types: DN and subjectDirectory
attributes, otherName SAN types, and certificate extensions.

Besides a magical ASN.1 DER/JER dumper/transcoder utility, we want to replace
DN attribute and subject alternative name (SAN) `otherName` tables and much
hand-coded handling of certificate extensions in `lib/hx509/`.

The reader should already be familiar with ASN.1, which anyways is a set of two
things:

 - an abstract syntax for specifying schemas for data interchange

 - a set of encoding rules

A very common thing to see in projects that use ASN.1, as well as projects that
use alternatives to ASN.1, is a pattern known as the "typed hole" or "open
type".

The ASN.1 Information Object System (IOS) [X.681] is all about automating the
otherwise very annoying task of dealing with "typed holes" / "open types".

The ASN.1 IOS is not sufficient to implement the magic we're after.  Also
needed is constraint specification and parameterization of types.

ITU-T references:

https://www.itu.int/rec/T-REC-X.680-201508-I/en
https://www.itu.int/rec/T-REC-X.681-201508-I/en
https://www.itu.int/rec/T-REC-X.682-201508-I/en
https://www.itu.int/rec/T-REC-X.683-201508-I/en


##Typed Holes / Open Types

A typed hole or open type is a pattern of data structure that generally looks
like:

```
    { type_id, bytes_encoding_a_value_of_a_type_identified_by_type_id }
```

I.e., an opaque datum and an identifier of what kind of datum that is.  This
happens because the structure with the typed hole is used in contexts where it
can't know all possible things that can go in it.  In many cases we do know
what all possible things are that can go in a typed hole, but many years ago
didn't, say, or anyways, had a reason to use a typed hole.

These are used not only in protocols that use ASN.1, but in many protocols that
use syntaxes and encodings unrelated to ASN.1.  I.e., these concepts are *not*
ASN.1-specific.

Many Internet protocols use typed holes, and many use ASN.1 and typed holes.
For example, PKIX, Kerberos, LDAP, and others, use ASN.1 and typed holes.

For an example of an Internet protocol that does not use ASN.1 but which still
has typed holes, see SSHv2.

In ASN.1 these generally look like:

```ASN.1
    TypedHole ::= SEQUENCE { typeId INTEGER, hole OCTET STRING }
```

or

```ASN.1
    TypedHole ::= SEQUENCE {
        typeId OBJECT IDENTIFIER,
        opaque ANY DEFINED BY typeID
    }
```

or

```ASN.1
    TypedHole ::= SEQUENCE {
        typeId OBJECT IDENTIFIER,
        opaque ANY -- DEFINED BY typeID
    }
```

or any number of variations.

    Note: the `ANY` variations are no longer conformant to X.680 (the base
    ASN.1 specification).

The pattern is `{ id, hole }` where the `hole` is ultimately an opaque sequence
of bytes whose content's schema is identified by the `id` in the same data
structure.  The pattern does not require just two fields, and it does not
require any particular type for the hole, nor for the type ID.  Sometimes the
"hole" is an `OCTET STRING`, sometimes it's a `BIT STRING`, sometimes it's an
`ANY` or `ANY DEFINED BY`.

An example from PKIX:

```ASN.1
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

```C
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

```C
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

```C
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


##ASN.1 IOS, Constraint, and Parameterization

The ASN.1 IOS is additional syntax that allows ASN.1 module authors to express
all the details about typed holes that ASN.1 compilers need to make developers'
lives much easier.

RFC5912 has lots of examples, such as this `CLASS` corresponding to the
`Extension` type from PKIX:

```ASN.1
  -- A class that provides some of the details of the PKIX Extension typed
  -- hole:
  EXTENSION ::= CLASS {
      -- The following are fields of a class (as opposed to "members" of
      -- SEQUENCE or SET types):
      &id  OBJECT IDENTIFIER UNIQUE,    -- This is a fixed-type value field.
                                        -- UNIQUE -> There can be only one
                                        --           object with this OID
                                        --           in any object set of
                                        --           this class.
                                        --           I.e., this is like a
                                        --           PRIMARY KEY in a SQL
                                        --           TABLE spec.
      &ExtnType,                        -- This is a type field (the hole).
      &Critical    BOOLEAN DEFAULT {TRUE | FALSE } -- fixed-type value set field.
  } WITH SYNTAX {
      -- This is a specification of easy to use (but hard-to-parse) syntax for
      -- specifying instances of this CLASS:
      SYNTAX &ExtnType IDENTIFIED BY &id
      [CRITICALITY &Critical]
  }

  -- Here's a parameterized Extension type.  The formal parameter is an as-yet
  -- unspecified set of valid things this hole can carry for some particular
  -- instance of this type.  The actual parameter will be specified later (see
  -- below).
  Extension{EXTENSION:ExtensionSet} ::= SEQUENCE {
      -- The type ID has to be the &id field of the EXTENSION CLASS of the
      -- ExtensionSet object set parameter.
      extnID      EXTENSION.&id({ExtensionSet}),
      -- This is the critical field, whose DEFAULT value should be that of
      -- the &Critical field of the EXTENSION CLASS of the ExtensionSet object
      -- set parameter.
      critical    BOOLEAN
  --                     (EXTENSION.&Critical({ExtensionSet}{@extnID}))
                       DEFAULT FALSE,
      -- Finally, the hole is an OCTET STRING constrained to hold the encoding
      -- of the type named by the &ExtnType field of the EXTENSION CLASS of the
      -- ExtensionSet object set parameter.
      --
      -- Note that for all members of this SEQUENCE, the fields of the object
      -- referenced must be of the same object in the ExtensionSet object set
      -- parameter.  That's how we get to say that some OID implies some type
      -- for the hole.
      extnValue   OCTET STRING (CONTAINING
                  EXTENSION.&ExtnType({ExtensionSet}{@extnID}))
                  --  contains the DER encoding of the ASN.1 value
                  --  corresponding to the extension type identified
                  --  by extnID
  }

  -- This is just a SEQUENCE of Extensions, the parameterized version.
  Extensions{EXTENSION:ExtensionSet} ::=
      SEQUENCE SIZE (1..MAX) OF Extension{{ExtensionSet}}
```

and these uses of it in RFC5280 (PKIX base):

```ASN.1
   -- Here we have an individual "object" specifying that the OID
   -- id-ce-authorityKeyIdentifier implies AuthorityKeyIdentifier as the hole
   -- type:
   ext-AuthorityKeyIdentifier EXTENSION ::= { SYNTAX
       AuthorityKeyIdentifier IDENTIFIED BY
       id-ce-authorityKeyIdentifier }

   -- And here's the OID, for completeness:
   id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
   ...

   -- And Here's an object set for the EXTENSION CLASS collecting a bunch of
   -- related extensions (here they are the extensions that certificates can
   -- carry in their extensions member):
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

   -- Lastly, we have a Certificate, and the place where the Extensions type's
   -- actual parameter is specified.
   --
   -- This is where the *rubber meets the road*!

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
                         -- ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                         -- The rubber meets the road *here*.
                         --
                         -- This says that the set of *known* certificate
                         -- extensions are those for which there are "objects"
                         -- in the "object set" named CertExtensions.
       ]], ... }
```

Notice that the `extensions` field of `TBSCertificate` is of type `Extensions`
parametrized by the `CertExtensions` information object set.

This allows the compiler to know that if any of the OIDs listed in the
`CertExtensions` object set appear as the actual value of the `extnID` member
of an `Extension` value, then the `extnValue` member of the same `Extension`
value must be an instance of the type associated with that OID.  For example,
an `Extension` with `extnID == id-ce-authorityKeyIdentifier` must have an
`extnValue` of type `AuthorityKeyIdentifier`.


###IOS Crash Course

The ASN.1 IOS is... a bit difficult to understand.  X.681 has a lot of strange
terminology, like "variable type value set field".  An IOS "class" has fields,
and those fields are of kind `[Fixed]Type[Value[Set]]` or `Object[Set]`.

Classes can have "object sets" associated with them, and each object set has
zero, one, or more "objects".  Each object has settings for all required fields
of a class, and possibly also for optional/defaulted fields as well.

IOS object sets really are akin to relational database tables, while objects
are akin to rows of the same.  And classes?  They're like a specification of
relational database tables that object sets derive.

So far, that is so useless to us: we have no need to specify constant (because
defined in compiled modules) relational data.

The magic for us lies in being able to document and constrain actual types
using IOS classes and object sets.  We want to use classes and object sets to
constrain `SET` or `SEQUENCE` types (well, really, just `SEQUENCE`) in such a
way that the compiler can auto-generate decoding and encoding of values of open
types.

`SET` and `SEQUENCE` types have "members".

Classes and objects have "fields".

Objects of a class have all the required fields of a class and any of the
`OPTIONAL` or `DEFAULT` fields of the class.  This is very similar to
`SET`/`SEQUENCE` members, which can be `OPTIONAL` or `DEFAULT`ed.

The "members" (we call them fields in C, instance variables in C++, Java, ...)
of a `SET` or `SEQUENCE` type are typed, just as in C, C++, Java, etc. for
struct or object types.

There are several kinds of fields of classes.  These can be confusing, so it's
essential that we explain them by reference to how they relate to the members
of `SEQUENCE` types derived from a class:

 - a `type field` of a class is one that specifies a SET or SEQUENCE member of
   unknown (open) type.

   The type of that SET or SEQUENCE member will not be not truly unknown, but
   determined by some other member of the SET or SEQUENCE, and that will be
   specified in a "value field" (or "value set" field) an "object" in an
   "object set" of that class.

 - a `fixed type value field` of a class is one that specifies a SET or
   SEQUENCE member of fixed type.

 - a `fixed type value set field` of a class is like a `fixed type value field`,
   but where object sets should provide a set of values for the SET or SEQUENCE
   member corresponding to the field.

 - a `variable type value [set] field` is one where the type of the SET or
   SEQUENCE member corresponding to the field will vary according to some
   specified `type field` of the same class.

 - an `object field` will be a field that names another class (possibly the
   same class), which can be used to provide rich hierarchical type semantics
   that... we don't need for PKIX.

 - similarly for `object set field`s.

As usual for ASN.1, the case of the first letter of a field name is meaningful:

 - value and object field names start with a lower case letter;
 - type, value set, and object set fields start with an upper-case letter;
 - object and object set fields are also known as `link fields`.

The form of a `fixed type value` field and a `fixed type value set` field is
the same, differing only the case of the first letter of the field name.
Similarly for `variable type value` and `variable type value set` fields.
Similarly, again, for `object` and `object set` fields.

Here's a simple example from PKIX:

```ASN.1
  -- An IOS class used to impose constraints on the PKIX Extension type:
  EXTENSION ::= CLASS {
      &id  OBJECT IDENTIFIER UNIQUE,
      &ExtnType,
      &Critical    BOOLEAN DEFAULT {TRUE | FALSE }
  } WITH SYNTAX {
      SYNTAX &ExtnType IDENTIFIED BY &id
      [CRITICALITY &Critical]
  }
```

 - The `&id` field is a fixed-type value field.  It's not a fixed-type value
   _set_ field because its identifier (`id`) starts with a lower-case letter.

   The `&id` field is intended to make the `extnId` member of the `Extension`
   `SEQUENCE` type name identify the actual type of the `extnValue` member of
   the same `SEQUENCE` type.

   The `UNIQUE` keyword tells us there can be only one object with any given
   value of this field in any object set of this class.

 - The `&ExtnType` field is a type field.  We can tell because no type is named
   in its declaration.

 - The `&Critical` field is a fixed-type value set field.  We can tell because
   it specifies a type (`BOOLEAN`) and starts with an upper-case letter.

   In-tree we could avoid having to implement fixed-type value set fields by
   renaming this one to `&critical` and eliding its `DEFAULT <ValueSet>` given
   that we know there are only two possible values for a `BOOLEAN` field.

 - Ignore the `WITH SYNTAX` clause for now.  All it does is specify a
   user-friendly butimplementor-hostile syntax for specifying objects for this
   class.

Note that none of the `Extension` extensions in PKIX actually specify
`CRITICALITY`/`&Critical`, so... we just don't need fixed-type value set
fields.  We could elide the `&Critical` field of the `EXTENSION` class
altogether.

Here's another, much more complex example from PKIX:

```ASN.1
  ATTRIBUTE ::= CLASS {
      &id             OBJECT IDENTIFIER UNIQUE,
      &Type           OPTIONAL,
      &equality-match MATCHING-RULE OPTIONAL,
      &minCount       INTEGER DEFAULT 1,
      &maxCount       INTEGER OPTIONAL
  }
  MATCHING-RULE ::= CLASS {
      &ParentMatchingRules   MATCHING-RULE OPTIONAL,
      &AssertionType         OPTIONAL,
      &uniqueMatchIndicator  ATTRIBUTE OPTIONAL,
      &id                    OBJECT IDENTIFIER UNIQUE
  }
```

 - For `ATTRIBUTE` the fields are:
    - The `&id` field is a fixed-type value field (intended to name the type of
      members linked to the `&Type` field).
    - The `&Type` field is a type field (open type).
    - The `&equality-match` is an object field linking to object sets of the
      `MATCHING-RULE` class.
    - The `minCount` and `maxCount` fields are fixed-type value fields.
 - For `MATCHING-RULE` the fields are:
    - The `&ParentMatchingRules` is an object set field linking to more
      `MATCHING-RULE`s.
    - The `&AssertionType` field is a type field (open type).
    - The `&uniqueMatchIndicator` field is an object field linking back to some
      object of the `ATTRIBUTE` class that indicates whether the match is
      unique (presumably).
    - The `&id` field is a fixed-type value field (intended to name the type of
      members linked to the `&AssertionType` field).

No `Attribute`s in PKIX specify matching rules, so we really don't need support
for object nor object set fields.

Because
 - no objects in object sets of `EXTENSION` in PKIX specify "criticality",
 - and no objects in object sets of `ATTRIBUTE` in PKIX specify matching rules,
 - and no matching rules are specified in PKIX.
we can drop `MATCHING-RULE` and simplify `ATTRIBUTE` and `EXTENSION` as:

```ASN.1
  EXTENSION ::= CLASS {
      &id  OBJECT IDENTIFIER UNIQUE,
      &ExtnType
  }
  ATTRIBUTE ::= CLASS {
      &id             OBJECT IDENTIFIER UNIQUE,
      &Type           OPTIONAL,
      &minCount       INTEGER DEFAULT 1,
      &maxCount       INTEGER OPTIONAL
  }
```

X.681 has an example in appendix D.2 that has at least one field of every kind.

Again, the rubber that are IOS classes and object sets meet the road when
defining types:

```ASN.1
  -- Define the Extension type but link it to the EXTENSION class so that
  -- an object set for that class can constrain it:
  Extension{EXTENSION:ExtensionSet} ::= SEQUENCE {
      extnID      EXTENSION.&id({ExtensionSet}),
      critical    BOOLEAN
                  (EXTENSION.&Critical({ExtensionSet}{@extnID}))
                  DEFAULT FALSE,
      extnValue   OCTET STRING (CONTAINING
                  EXTENSION.&ExtnType({ExtensionSet}{@extnID}))
  }
  -- Most members of TBSCertificate elided for brevity:
  TBSCertificate  ::=  SEQUENCE  {
      ...,
      extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
                                   -- ^^^^^^^^^^^^^^^^
                                   -- the rubber meets the road here!!
      ...
  }

  OTHER-NAME ::= TYPE-IDENTIFIER
  -- Most members of GeneralName elided for brevity:
  GeneralName ::= CHOICE {
      otherName       [0]  INSTANCE OF OTHER-NAME({OtherNames}),
                                               -- ^^^^^^^^^^^^
                                               -- rubber & road meet!
      ...
  }
```

(The `CertExtensions` and `OtherNames` object sets are not shown here for
brevity.  PKIX doesn't even define an `OtherNames` object set, though it well
could.)

The above demonstrates two ways to create `SEQUENCE` types that are constrained
by IOS classes.  One is by defining the types of the members of a `SEQUENCE`
type by reference to class fields.  The other is by using `INSTANCE OF` to say
that the class defines the type directly.  The first lets us do things like
have a mix members of a `SEQUENCE` type where some are defined by relation to a
class and others are not, or where multiple classes are used.

In the case of `INSTANCE OF`, what shall the names of the members of the
derived type be?  Well, such types can _only_ be instances of `TYPE-IDENTIFIER`
or classes isomorphic to it (as `OTHER-NAME` is in the above exammle), and so
the names of their two members are just baked in by X.681 annex C.1 as:

```ASN.1
    SEQUENCE {
        type-id     <DefinedObjectClass>.&id,
        value[0]    <DefinedObjectClass>.&Type
    }
    -- where <DefinedObjectClass> is the name of the class, which has to be
    -- `TYPE-IDENTIFIER` or exactly like it.
```

(This means we can't use `INSTANCE OF` with `EXTENSION`.)

PKIX has much more complex classes for relating and constraining cryptographic
algorithms and their parameters:

 - `DIGEST-ALGORITHM`,
 - `SIGNATURE-ALGORITHM`,
 - `PUBLIC-KEY`,
 - `KEY-TRANSPORT`,
 - `KEY-AGREE`,
 - `KEY-WRAP`,
 - `KEY-DERIVATION`,
 - `MAC-ALGORITHM`,
 - `CONTENT-ENCRYPTION`,
 - `ALGORITHM`,
 - `SMIME-CAPS`,
 - and `CURVE`.

These show the value of just the relational data aspect of IOS.  They can not
only be used by the codecs at run-time to perform validation of, e.g.,
cryptographic algorithm parameters, but also to provide those rules to other
code in the application so that the programmer doesn't have to manually write
the same in C, C++, Java, etc, and can refer to them when applying those
cryptographic algorithms.


##Implementation Thoughts

 - The required specifications, X.681, X.682, and X.683, are fairly large and
   non-trivial.  Perhaps we can implement just the subset of those three that
   we need to implement PKIX, just as we already implement just the subset of
   X.680 that we need to implement PKIX and Kerberos.

   For dealing with PKIX, the bare minimum of IOS classes we should want are:

    - `ATTRIBUTE` (used for `DN` attributes in RFC5280)
    - `EXTENSION` (used for certificate extensions in RFC5280)
    - `TYPE-IDENTIFIER` (used for `OtherName` and for CMS' `Content-Type`)

   The minimal subset of X.681, X.682, and X.683 needed to implement those
   three is all we need.  Eventually we may want to increase that subset so as
   to implement other IOS classes from PKIX, such as `DIGEST-ALGORITHM`

   Note that there's no object set specified for OTHER-NAME instances, but we
   can create our own, and will.  We want magic open type decoding to recurse
   all the way down and handle DN attributes, extensions, SANs, policy
   qualifiers, the works.

 - We'll really want to do this mainly for the template compiler and begin
   abandoning the original compiler -- hacking on two compilers is difficult,
   and the template compiler is superior just on account of emitted code size
   scaling as `O(N)` instead of `O(M * N)` where `M` is the number of encoding
   rules supported and `N` is the number of types in an ASN.1 module (or all
   modules).

 - Also, to make the transition to using IOS in-tree, we'll want to keep
   existing fields of C structures as generated by the compiler today, only
   adding new ones, that way code that hasn't been updated to use the automatic
   encoding/decoding can still work and we can then update Heimdal in-tree
   slowly to take advantage of the new magic.

   Thus `Extension` should compile to:

```C
    typedef struct Extension {
      -- Existing fields:
      heim_oid extnID;
      int *critical;
      heim_octet_string extnValue;
      -- New, CHOICE-like fields:
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
   `_ioselement` and `_iosu` fields and ignore the `extnID` and `extnValue`
   fields.

   In both cases, the `critical` field should get used as-is.  The rule should
   be that we support *two* special fields: a hole type ID enum field, and a
   decoded hole value union.  All other fields will map to either normal
   members of the SET/SEQUENCE, or to members that are derived from a CLASS but
   which are neither hole type ID fields nor hole fields.

 - Type ID values must get mapped to discrete enum values.  We'll want type IDs
   to be sorted, too, so that we can binary search the "object set" when
   decoding.  For encoding we'll want to "switch" on the mapped type ID enum.

 - The ASN.1 parser merely builds an AST.  That will not change.

 - The C header generator will remain shared between the two backends.

 - Only the template backend will support the ASN.1 IOS.  We'll basically
   encode a new template for the combination of object set and typed hole
   container type.  This will come with a header entry indicating how many
   items are in the object set, and each item will be one entry pointing to the
   template for one particular object in the object set.  The template for each
   object will identify the type ID and the template for the associated type.

   Perhaps we'll inline the objects for locality of reference.

