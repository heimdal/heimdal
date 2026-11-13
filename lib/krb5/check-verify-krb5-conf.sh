#!/bin/sh
#
# Exercise verify_krb5_conf(8).  This is run from the build directory by
# "make check", which exports $srcdir.

srcdir=${srcdir:-.}
verify=./verify_krb5_conf

ec=0
fail() { echo "FAILED: $*"; ec=1; }

cat > vkc-good.conf <<EOC
[libdefaults]
	default_realm = EXAMPLE.ORG
	clockskew = 5m
	ticket_lifetime = 1d
	renew_lifetime = 7d
	forwardable = true
	dns_lookup_kdc = no
	default_etypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
	max_retries = 3

[realms]
	EXAMPLE.ORG = {
		kdc = localhost:88
		kdc = 127.0.0.1
		admin_server = localhost
		kpasswd_server = localhost
		default_domain = example.org
	}

[domain_realm]
	.example.org = EXAMPLE.ORG

[kdc]
	require-preauth = true
	kdc_warn_pwexpire = 1w
	ports = 88 750

[logging]
	kdc = FILE:/var/log/kdc.log
	default = SYSLOG:INFO:AUTH
	kadmind = 0-/STDERR

[kadmin]
	password_lifetime = 90d
	default_keys = aes256-cts-hmac-sha1-96:pw-salt

[password_quality]
	min_length = 8
EOC

cat > vkc-bad.conf <<EOC
[libdefaults]
	default_realm = EXAMPLE.ORG
	clockskew = not-a-time
	forwardable = maybe
	max_retries = many
	no_such_libdefault = 1
	default_etypes = no-such-enctype

[realms]
	EXAMPLE.ORG = {
		kdc = localhost:88
		no_such_realm_option = x
	}

[logging]
	kdc = BOGUS:/var/log/kdc.log

[no_such_section]
	foo = bar
EOC

${verify} --version > /dev/null || fail "--version"
${verify} vkc-good.conf || fail "good config rejected"
${verify} --dumpconfig vkc-good.conf | grep 'EXAMPLE.ORG' > /dev/null ||
    fail "--dumpconfig"
${verify} --warn-mit-syntax vkc-good.conf || fail "--warn-mit-syntax"
${verify} vkc-bad.conf 2> vkc-bad.err && fail "bad config accepted"
for what in clockskew forwardable max_retries no_such_libdefault \
            no_such_realm_option no_such_section /logging/kdc; do
    grep "$what" vkc-bad.err > /dev/null || fail "no complaint about $what"
done
${verify} no-such-file.conf 2>/dev/null && fail "missing file accepted"
printf '[libdefaults\n\tfoo = bar\n' > vkc-syntax.conf
${verify} vkc-syntax.conf 2>/dev/null && fail "syntax error accepted"

rm -f vkc-good.conf vkc-bad.conf vkc-bad.err vkc-syntax.conf
exit $ec
