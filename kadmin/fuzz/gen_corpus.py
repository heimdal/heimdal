#!/usr/bin/env python3
"""
Generate fuzz corpus for kadmind RPC testing.

Message format:
  4-byte big-endian length prefix
  N bytes of message data

The message data starts with a 4-byte command number (kadm_ops enum).

The fuzzer pre-populates the HDB with these principals (in FUZZ.REALM):
  - test
  - admin/admin
  - user1
  - user2
  - host/localhost
  - HTTP/www.example.com
  - krbtgt/FUZZ.REALM
"""

import struct
import os

# kadm_ops enum values
KADM_GET = 0
KADM_DELETE = 1
KADM_CREATE = 2
KADM_RENAME = 3
KADM_CHPASS = 4
KADM_MODIFY = 5
KADM_RANDKEY = 6
KADM_GET_PRIVS = 7
KADM_GET_PRINCS = 8
KADM_CHPASS_WITH_KEY = 9
KADM_NOP = 10
KADM_PRUNE = 11

# Pre-populated principals (must match kadmind.c fuzz_stdin)
EXISTING_PRINCIPALS = [
    "test",
    "admin/admin",
    "user1",
    "user2",
    "host/localhost",
    "HTTP/www.example.com",
    "krbtgt/FUZZ.REALM",
]

# KADM5 mask bits (from admin.h)
KADM5_PRINCIPAL = 0x000001
KADM5_PRINC_EXPIRE_TIME = 0x000002
KADM5_PW_EXPIRATION = 0x000004
KADM5_LAST_PWD_CHANGE = 0x000008
KADM5_ATTRIBUTES = 0x000010
KADM5_MAX_LIFE = 0x000020
KADM5_MOD_TIME = 0x000040
KADM5_MOD_NAME = 0x000080
KADM5_KVNO = 0x000100
KADM5_MKVNO = 0x000200
KADM5_AUX_ATTRIBUTES = 0x000400
KADM5_POLICY = 0x000800
KADM5_POLICY_CLR = 0x001000
KADM5_MAX_RLIFE = 0x002000
KADM5_LAST_SUCCESS = 0x004000
KADM5_LAST_FAILED = 0x008000
KADM5_FAIL_AUTH_COUNT = 0x010000
KADM5_KEY_DATA = 0x020000
KADM5_TL_DATA = 0x040000


def pack_int32(val):
    """Pack a 32-bit big-endian integer."""
    return struct.pack('>i', val)


def pack_uint32(val):
    """Pack a 32-bit big-endian unsigned integer."""
    return struct.pack('>I', val)


def pack_string(s):
    """Pack a string (4-byte length + data + null terminator)."""
    # Heimdal krb5_store_string includes null terminator in length
    data = s.encode('utf-8') + b'\x00'
    return pack_uint32(len(data)) + data


def pack_data(d):
    """Pack binary data (4-byte length + data)."""
    return pack_uint32(len(d)) + d


def pack_principal(name, realm="FUZZ.REALM"):
    """
    Pack a Kerberos principal.
    Format: name_type (4), num_components (4), realm (string),
            components (string each)
    """
    parts = name.split('/')
    # KRB5_NT_PRINCIPAL = 1
    result = pack_int32(1)  # name_type
    result += pack_int32(len(parts))  # num_components
    result += pack_string(realm)  # realm
    for part in parts:
        result += pack_string(part)
    return result


def pack_principal_ent(principal_name, mask, realm="FUZZ.REALM"):
    """
    Pack a kadm5_principal_ent structure.
    Only includes fields indicated by mask.
    """
    result = pack_int32(mask)  # mask comes first

    if mask & KADM5_PRINCIPAL:
        result += pack_principal(principal_name, realm)
    if mask & KADM5_PRINC_EXPIRE_TIME:
        result += pack_int32(0)  # princ_expire_time
    if mask & KADM5_PW_EXPIRATION:
        result += pack_int32(0)  # pw_expiration
    if mask & KADM5_LAST_PWD_CHANGE:
        result += pack_int32(0)  # last_pwd_change
    if mask & KADM5_MAX_LIFE:
        result += pack_int32(86400)  # max_life = 1 day
    if mask & KADM5_MOD_NAME:
        result += pack_int32(0)  # mod_name is NULL
    if mask & KADM5_MOD_TIME:
        result += pack_int32(0)  # mod_date
    if mask & KADM5_ATTRIBUTES:
        result += pack_int32(0)  # attributes
    if mask & KADM5_KVNO:
        result += pack_int32(1)  # kvno
    if mask & KADM5_MKVNO:
        result += pack_int32(1)  # mkvno
    if mask & KADM5_POLICY:
        result += pack_int32(0)  # policy is NULL
    if mask & KADM5_AUX_ATTRIBUTES:
        result += pack_int32(0)  # aux_attributes
    if mask & KADM5_MAX_RLIFE:
        result += pack_int32(604800)  # max_renewable_life = 1 week
    if mask & KADM5_LAST_SUCCESS:
        result += pack_int32(0)
    if mask & KADM5_LAST_FAILED:
        result += pack_int32(0)
    if mask & KADM5_FAIL_AUTH_COUNT:
        result += pack_int32(0)
    if mask & KADM5_KEY_DATA:
        result += pack_int32(0)  # n_key_data = 0
    if mask & KADM5_TL_DATA:
        result += pack_int32(0)  # n_tl_data = 0

    return result


def wrap_message(data):
    """Wrap message data with 4-byte length prefix."""
    return pack_uint32(len(data)) + data


def write_corpus(filename, data):
    """Write a corpus file."""
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path, 'wb') as f:
        f.write(wrap_message(data))
    print(f"Created {filename} ({len(data)} bytes payload)")


# Generate corpus files

# ========== Basic operations ==========

# 1. NOP with reply wanted
write_corpus("nop_reply.bin",
    pack_int32(KADM_NOP) + pack_int32(1))

# 2. NOP without reply (interrupt request)
write_corpus("nop_noreply.bin",
    pack_int32(KADM_NOP) + pack_int32(0))

# 3. GET_PRIVS
write_corpus("get_privs.bin",
    pack_int32(KADM_GET_PRIVS))

# ========== Operations on EXISTING principals ==========
# These should exercise deeper code paths since the principals exist

# 4. GET existing principal "test"
write_corpus("get_existing_test.bin",
    pack_int32(KADM_GET) +
    pack_principal("test") +
    pack_int32(KADM5_PRINCIPAL | KADM5_KVNO | KADM5_ATTRIBUTES))

# 5. GET existing principal with all fields
write_corpus("get_existing_all.bin",
    pack_int32(KADM_GET) +
    pack_principal("test") +
    pack_int32(0x7FFFF))  # All mask bits

# 6. GET existing admin/admin
write_corpus("get_existing_admin.bin",
    pack_int32(KADM_GET) +
    pack_principal("admin/admin") +
    pack_int32(KADM5_PRINCIPAL | KADM5_KVNO))

# 7. GET existing host principal
write_corpus("get_existing_host.bin",
    pack_int32(KADM_GET) +
    pack_principal("host/localhost") +
    pack_int32(KADM5_PRINCIPAL | KADM5_KEY_DATA))

# 8. GET existing HTTP service
write_corpus("get_existing_http.bin",
    pack_int32(KADM_GET) +
    pack_principal("HTTP/www.example.com") +
    pack_int32(KADM5_PRINCIPAL))

# 9. GET krbtgt (special principal)
write_corpus("get_existing_krbtgt.bin",
    pack_int32(KADM_GET) +
    pack_principal("krbtgt/FUZZ.REALM") +
    pack_int32(KADM5_PRINCIPAL | KADM5_KVNO | KADM5_MAX_LIFE))

# 10. CHPASS on existing principal
write_corpus("chpass_existing.bin",
    pack_int32(KADM_CHPASS) +
    pack_principal("user1") +
    pack_string("newpassword123") +
    pack_int32(0))  # keepold = false

# 11. CHPASS on existing with keepold
write_corpus("chpass_existing_keepold.bin",
    pack_int32(KADM_CHPASS) +
    pack_principal("user2") +
    pack_string("anotherpassword") +
    pack_int32(1))  # keepold = true

# 12. RANDKEY on existing principal
write_corpus("randkey_existing.bin",
    pack_int32(KADM_RANDKEY) +
    pack_principal("test"))

# 13. RANDKEY on existing with ks_tuples
write_corpus("randkey_existing_full.bin",
    pack_int32(KADM_RANDKEY) +
    pack_principal("user1") +
    pack_int32(1) +  # keepold
    pack_int32(2) +  # n_ks_tuple
    pack_int32(17) + pack_int32(0) +  # aes128-cts-hmac-sha1-96
    pack_int32(18) + pack_int32(0))   # aes256-cts-hmac-sha1-96

# 14. MODIFY existing principal
mask = KADM5_PRINCIPAL | KADM5_ATTRIBUTES | KADM5_MAX_LIFE
write_corpus("modify_existing.bin",
    pack_int32(KADM_MODIFY) +
    pack_principal_ent("test", mask) +
    pack_int32(mask))

# 15. MODIFY existing - change max_renewable_life
mask = KADM5_PRINCIPAL | KADM5_MAX_RLIFE
write_corpus("modify_existing_rlife.bin",
    pack_int32(KADM_MODIFY) +
    pack_principal_ent("user1", mask) +
    pack_int32(mask))

# 16. PRUNE existing principal
write_corpus("prune_existing.bin",
    pack_int32(KADM_PRUNE) +
    pack_principal("test") +
    pack_int32(1))  # keep kvno >= 1

# 17. RENAME existing to new
write_corpus("rename_existing.bin",
    pack_int32(KADM_RENAME) +
    pack_principal("user2") +
    pack_principal("user2_renamed"))

# 18. CHPASS_WITH_KEY on existing
key_data = (
    pack_int32(2) +  # key_data_ver
    pack_int32(2) +  # key_data_kvno
    pack_int32(17) +  # aes128
    pack_data(b'\x00' * 16) +
    pack_int32(0) +  # no salt type
    pack_data(b'')
)
write_corpus("chpass_key_existing.bin",
    pack_int32(KADM_CHPASS_WITH_KEY) +
    pack_principal("test") +
    pack_int32(1) +  # n_key_data
    pack_int32(0) +  # keepold
    key_data)

# ========== Operations on NON-EXISTING principals ==========

# 19. GET non-existing principal
write_corpus("get_nonexisting.bin",
    pack_int32(KADM_GET) +
    pack_principal("does/not/exist") +
    pack_int32(KADM5_PRINCIPAL))

# 20. DELETE non-existing principal
write_corpus("delete_nonexisting.bin",
    pack_int32(KADM_DELETE) +
    pack_principal("nonexistent"))

# 21. CREATE new principal
mask = KADM5_PRINCIPAL | KADM5_MAX_LIFE | KADM5_MAX_RLIFE
write_corpus("create_new.bin",
    pack_int32(KADM_CREATE) +
    pack_principal_ent("newprinc", mask) +
    pack_int32(mask) +
    pack_string("password123"))

# 22. CREATE with various attributes
mask = KADM5_PRINCIPAL | KADM5_ATTRIBUTES | KADM5_MAX_LIFE | KADM5_PRINC_EXPIRE_TIME
write_corpus("create_with_attrs.bin",
    pack_int32(KADM_CREATE) +
    pack_principal_ent("newprinc2", mask) +
    pack_int32(mask) +
    pack_string("password456"))

# ========== GET_PRINCS listing ==========

# 23. GET_PRINCS - list all
write_corpus("get_princs_all.bin",
    pack_int32(KADM_GET_PRINCS) +
    pack_int32(0))  # no expression

# 24. GET_PRINCS with wildcard
write_corpus("get_princs_wildcard.bin",
    pack_int32(KADM_GET_PRINCS) +
    pack_int32(1) +
    pack_string("*"))

# 25. GET_PRINCS with pattern
write_corpus("get_princs_user.bin",
    pack_int32(KADM_GET_PRINCS) +
    pack_int32(1) +
    pack_string("user*"))

# 26. GET_PRINCS with host pattern
write_corpus("get_princs_host.bin",
    pack_int32(KADM_GET_PRINCS) +
    pack_int32(1) +
    pack_string("host/*"))

# 27. GET_PRINCS online iteration mode
write_corpus("get_princs_iter.bin",
    pack_int32(KADM_GET_PRINCS) +
    pack_int32(0x55555555) +
    pack_string("*"))

# ========== Edge cases and malformed inputs ==========

# 28. Invalid command
write_corpus("invalid_cmd.bin",
    pack_int32(99))

# 29. Truncated message
write_corpus("truncated_get.bin",
    pack_int32(KADM_GET))

# 30. Malformed principal (bad component count)
write_corpus("malformed_principal.bin",
    pack_int32(KADM_GET) +
    pack_int32(1) +  # name_type
    pack_int32(-1) +  # invalid num_components
    pack_string("FUZZ.REALM"))

# 31. Very long principal name
write_corpus("long_principal.bin",
    pack_int32(KADM_GET) +
    pack_principal("A" * 1000))

# 32. Principal with many components
write_corpus("many_components.bin",
    pack_int32(KADM_GET) +
    pack_principal("/".join(["c"] * 50)))

# 33. Empty password create
mask = KADM5_PRINCIPAL
write_corpus("create_empty_password.bin",
    pack_int32(KADM_CREATE) +
    pack_principal_ent("emptypass", mask) +
    pack_int32(mask) +
    pack_string(""))

# 34. Create with TL_DATA
mask = KADM5_PRINCIPAL | KADM5_TL_DATA
tl_data = (
    pack_int32(1) +  # tl_data_type
    pack_data(b'test tl data content')
)
princ_with_tl = (
    pack_int32(mask) +
    pack_principal("withtldata") +
    pack_int32(1) +  # n_tl_data
    tl_data
)
write_corpus("create_with_tldata.bin",
    pack_int32(KADM_CREATE) +
    princ_with_tl +
    pack_int32(mask) +
    pack_string("password"))

# 35. Large n_key_data (integer overflow)
write_corpus("large_nkeydata.bin",
    pack_int32(KADM_CHPASS_WITH_KEY) +
    pack_principal("test") +
    pack_int32(0x7FFFFFFF) +
    pack_int32(0))

# 36. Negative n_key_data
write_corpus("negative_nkeydata.bin",
    pack_int32(KADM_CHPASS_WITH_KEY) +
    pack_principal("test") +
    pack_int32(-1) +
    pack_int32(0))

# 37. Zero-length message
with open(os.path.join(os.path.dirname(__file__), "empty_message.bin"), 'wb') as f:
    f.write(pack_uint32(0))
print("Created empty_message.bin (0 bytes payload)")

# 38. Multiple key_data entries
multi_key = b''
for i in range(3):
    multi_key += (
        pack_int32(2) +  # ver
        pack_int32(i + 1) +  # kvno
        pack_int32(17) +  # aes128
        pack_data(b'\x00' * 16) +
        pack_int32(0) +
        pack_data(b'')
    )
write_corpus("chpass_multikey.bin",
    pack_int32(KADM_CHPASS_WITH_KEY) +
    pack_principal("test") +
    pack_int32(3) +  # n_key_data
    pack_int32(1) +  # keepold
    multi_key)

# 39. MODIFY with policy (even though we don't have policies)
mask = KADM5_PRINCIPAL | KADM5_POLICY
write_corpus("modify_with_policy.bin",
    pack_int32(KADM_MODIFY) +
    pack_int32(mask) +
    pack_principal("test") +
    pack_int32(1) +  # policy is present
    pack_string("default") +
    pack_int32(mask))

# 40. DELETE existing principal (exercising actual delete path)
write_corpus("delete_existing.bin",
    pack_int32(KADM_DELETE) +
    pack_principal("user1"))

# 41. Cross-realm principal reference
write_corpus("get_crossrealm.bin",
    pack_int32(KADM_GET) +
    pack_principal("user", "OTHER.REALM") +
    pack_int32(KADM5_PRINCIPAL))

# 42. Service principal with instance
write_corpus("create_service.bin",
    pack_int32(KADM_CREATE) +
    pack_principal_ent("ldap/server.example.com", KADM5_PRINCIPAL | KADM5_MAX_LIFE) +
    pack_int32(KADM5_PRINCIPAL | KADM5_MAX_LIFE) +
    pack_string("servicepass"))

print("\nCorpus generation complete!")
