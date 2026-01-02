/* $Id$ */

#include <stddef.h>
#include <time.h>
#include <krb5-types.h>

#ifndef __asn1_common_definitions__
#define __asn1_common_definitions__

#ifndef __HEIM_BASE_DATA__
#define __HEIM_BASE_DATA__ 1
struct heim_base_data {
	size_t length;
	void *data;
};
#endif

typedef struct heim_integer {
    size_t length;
    void *data;
    int negative;
} heim_integer;

typedef struct heim_base_data heim_octet_string;

typedef char *heim_general_string;
typedef char *heim_utf8_string;
typedef struct heim_base_data heim_printable_string;
typedef struct heim_base_data heim_ia5_string;

typedef struct heim_bmp_string {
    size_t length;
    uint16_t *data;
} heim_bmp_string;

typedef struct heim_universal_string {
    size_t length;
    uint32_t *data;
} heim_universal_string;

typedef char *heim_visible_string;

typedef struct heim_oid {
    size_t length;
    unsigned *components;
} heim_oid;

typedef struct heim_bit_string {
    size_t length;
    void *data;
} heim_bit_string;

typedef struct heim_base_data heim_any;
typedef struct heim_base_data heim_any_set;
typedef struct heim_base_data HEIM_ANY;
typedef struct heim_base_data HEIM_ANY_SET;

enum asn1_print_flags {
    ASN1_PRINT_INDENT = 1,
};

#define ASN1_MALLOC_ENCODE(T, B, BL, S, L, R)                  \
  do {                                                         \
    (BL) = length_##T((S));                                    \
    (B) = malloc((BL));                                        \
    if((B) == NULL) {                                          \
      (R) = ENOMEM;                                            \
    } else {                                                   \
      (R) = encode_##T(((unsigned char*)(B)) + (BL) - 1, (BL), \
                       (S), (L));                              \
      if((R) != 0) {                                           \
        free((B));                                             \
        (B) = NULL;                                            \
      }                                                        \
    }                                                          \
  } while (0)

#define ASN1_MALLOC_ENCODE_SAVE(T, S, L, R)                     \
    do {                                                        \
        der_free_octet_string(&(S)->_save);                     \
        ASN1_MALLOC_ENCODE(T, (S)->_save.data,                  \
                           (S)->_save.length, (S), (L), (R));   \
    } while (0)

#if defined(_WIN32) && !defined(__MINGW32__)
#ifndef ASN1_LIB
#define ASN1EXP  __declspec(dllimport)
#else
#define ASN1EXP
#endif
#define ASN1CALL __stdcall
#elif defined(_WIN32)
/* MinGW - static linking, use __cdecl */
#define ASN1EXP
#define ASN1CALL __cdecl
#else
#define ASN1EXP
#define ASN1CALL
#endif

#endif
