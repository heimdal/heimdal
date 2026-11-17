#!/bin/sh
#
# Exercise asn1_print(1) on DER samples from the tree.  This is run from
# the build directory by "make check", which exports $srcdir.

srcdir=${srcdir:-.}
hxdata="$srcdir/../hx509/data"
asn1_print=./asn1_print

ec=0
fail() { echo "FAILED: $*"; ec=1; }

${asn1_print} --version > /dev/null || fail "--version"
${asn1_print} --list-types > out-asn1-types || fail "--list-types"
grep '^Certificate$' out-asn1-types > /dev/null ||
    fail "--list-types does not list Certificate"

cert="$srcdir/data/test_ios_cert.der"

# Untyped (raw BER) dumps, with and without indentation / inner parsing
${asn1_print} "$cert" > /dev/null || fail "raw dump"
${asn1_print} --no-indent --inner --raw-sequence "$cert" > /dev/null ||
    fail "raw dump -i -I -S"

# Typed dumps (JSON), round-trip encode/copy, quiet mode
${asn1_print} "$cert" Certificate | grep '"_type":"Certificate"' > /dev/null ||
    fail "Certificate JSON dump"
${asn1_print} --test-encode --test-copy "$cert" Certificate > /dev/null ||
    fail "--test-encode --test-copy"
${asn1_print} --no-print --test-encode "$cert" Certificate > /dev/null ||
    fail "--no-print"
${asn1_print} --quiet "$hxdata/crl1.der" CRLCertificateList ||
    fail "CRLCertificateList"
${asn1_print} --quiet "$hxdata/ocsp-resp1.der" OCSPResponse ||
    fail "OCSPResponse"
${asn1_print} --quiet "$hxdata/ocsp-req1.der" OCSPRequest ||
    fail "OCSPRequest"
${asn1_print} --quiet "$hxdata/key.der" Certificate 2>/dev/null &&
    fail "key.der decoded as Certificate"
${asn1_print} --quiet "$cert" NoSuchType 2>/dev/null &&
    fail "unknown type accepted"

# Try every known type on a few inputs
for f in "$cert" "$hxdata/crl1.der" "$hxdata/ocsp-resp1.der" \
         "$hxdata/secp256r1TestCA.cert.der" \
         "$hxdata/win-u16-in-printablestring.der"; do
    ${asn1_print} --try-all-types "$f" > out-asn1-all 2>&1 ||
        fail "--try-all-types $f"
    grep '^Match: ' out-asn1-all > /dev/null || fail "no type matched $f"
done

${asn1_print} "$srcdir/no-such-file.der" 2>/dev/null && fail "missing file"

rm -f out-asn1-types out-asn1-all
exit $ec
