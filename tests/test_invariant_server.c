#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

/*
 * Security invariant: When allocating an array of key_data elements,
 * the multiplication of n_key_data * sizeof(element) must never overflow,
 * and the resulting allocation must be large enough to hold all elements.
 * If overflow would occur, the allocation must be rejected (NULL returned
 * or the count must be validated before allocation).
 */

/* Simulate the element size as in the vulnerable code */
typedef struct {
    unsigned int key_data_ver;
    unsigned int key_data_kvno;
    unsigned short key_data_type[2];
    unsigned short key_data_length[2];
    unsigned char *key_data_contents[2];
} krb5_key_data_sim;

/*
 * Safe allocation function that checks for integer overflow before
 * performing the multiplication. This is what the fixed code MUST do.
 */
static void *safe_alloc_key_data(size_t n_key_data)
{
    /* Security invariant: must detect overflow before allocation */
    if (n_key_data == 0) {
        return NULL;
    }

    /* Check for multiplication overflow */
    if (n_key_data > SIZE_MAX / sizeof(krb5_key_data_sim)) {
        /* Overflow would occur - must reject */
        return NULL;
    }

    size_t alloc_size = n_key_data * sizeof(krb5_key_data_sim);

    /* Additional sanity check: allocation size must be >= n_key_data * element_size */
    if (alloc_size < n_key_data * sizeof(krb5_key_data_sim)) {
        return NULL;
    }

    return malloc(alloc_size);
}

/*
 * Verify that for a given n_key_data value, if allocation succeeds,
 * the allocated buffer is large enough to hold all elements safely.
 */
static int allocation_is_safe(size_t n_key_data)
{
    /* Check overflow condition */
    if (n_key_data > SIZE_MAX / sizeof(krb5_key_data_sim)) {
        return 0; /* Would overflow - unsafe */
    }

    size_t required = n_key_data * sizeof(krb5_key_data_sim);

    /* Verify no overflow occurred in the multiplication itself */
    if (n_key_data != 0 && required / n_key_data != sizeof(krb5_key_data_sim)) {
        return 0; /* Overflow detected - unsafe */
    }

    return 1; /* Safe */
}

START_TEST(test_key_data_allocation_overflow)
{
    /* Invariant: n_key_data * sizeof(key_data_element) must never overflow,
     * and any allocation based on n_key_data must be large enough to hold
     * all n_key_data elements without buffer overflow. */

    /* Adversarial n_key_data values that could cause integer overflow */
    size_t adversarial_counts[] = {
        /* Values near SIZE_MAX / sizeof(element) boundary */
        SIZE_MAX / sizeof(krb5_key_data_sim) + 1,
        SIZE_MAX / sizeof(krb5_key_data_sim) + 2,
        SIZE_MAX,
        SIZE_MAX - 1,
        SIZE_MAX / 2 + 1,
        /* Classic overflow values for 32-bit wrapping on 64-bit */
        (size_t)0x100000000ULL,
        (size_t)0xFFFFFFFFULL,
        (size_t)0x80000000ULL,
        /* Values that cause small allocation after overflow */
        (size_t)(SIZE_MAX / sizeof(krb5_key_data_sim)) + 100,
        /* Boundary: exactly at overflow threshold */
        SIZE_MAX / sizeof(krb5_key_data_sim),
        /* Large but potentially valid */
        0x10000000,
        0x7FFFFFFF,
        /* Zero and one */
        0,
        1,
        /* Small safe values */
        2,
        10,
        100,
    };

    int num_counts = sizeof(adversarial_counts) / sizeof(adversarial_counts[0]);

    for (int i = 0; i < num_counts; i++) {
        size_t n_key_data = adversarial_counts[i];

        /* Test the safe allocation function */
        void *ptr = safe_alloc_key_data(n_key_data);

        if (ptr != NULL) {
            /* If allocation succeeded, it must be safe (no overflow) */
            ck_assert_msg(allocation_is_safe(n_key_data),
                "SECURITY VIOLATION: Allocation succeeded for n_key_data=%zu "
                "but multiplication would overflow, creating undersized buffer",
                n_key_data);

            /* Verify the allocated size is actually sufficient */
            size_t required_size = n_key_data * sizeof(krb5_key_data_sim);
            ck_assert_msg(required_size >= n_key_data,
                "SECURITY VIOLATION: required_size calculation overflowed for n_key_data=%zu",
                n_key_data);

            free(ptr);
        } else {
            /* Allocation returned NULL - either overflow detected or OOM */
            /* If it's an overflow case, NULL is the correct safe behavior */
            if (!allocation_is_safe(n_key_data)) {
                /* Correct: overflow was detected and rejected */
                ck_assert_msg(1, "Correctly rejected overflow for n_key_data=%zu", n_key_data);
            }
            /* If allocation_is_safe but NULL returned, it's just OOM - acceptable */
        }

        /* Core invariant: for any n_key_data that would overflow,
         * the unsafe (vulnerable) allocation pattern must be detectable */
        if (n_key_data > 0 && n_key_data > SIZE_MAX / sizeof(krb5_key_data_sim)) {
            /* This is an overflow case - verify our detection works */
            size_t unsafe_size = n_key_data * sizeof(krb5_key_data_sim);
            /* After overflow, unsafe_size will be smaller than expected */
            ck_assert_msg(unsafe_size < n_key_data || unsafe_size == 0,
                "SECURITY CHECK: Overflow detection failed for n_key_data=%zu, "
                "unsafe_size=%zu should be smaller due to wrap-around",
                n_key_data, unsafe_size);
        }
    }
}
END_TEST

START_TEST(test_key_data_count_validation)
{
    /* Invariant: n_key_data derived from network input must be validated
     * against a reasonable maximum before use in size calculations */

    /* Simulate values that might come from a kadmin protocol message */
    uint32_t protocol_values[] = {
        0xFFFFFFFF,  /* Max uint32 */
        0x80000000,  /* High bit set */
        0x7FFFFFFF,  /* Max int32 */
        0x10000000,  /* Large value */
        0x00FFFFFF,  /* 16M entries */
        0x0000FFFF,  /* 64K entries */
        0x00000000,  /* Zero */
        0x00000001,  /* One */
        0x00000002,  /* Two */
        /* Values that when multiplied by sizeof(krb5_key_data_sim) overflow 32-bit */
        (uint32_t)(0x100000000ULL / sizeof(krb5_key_data_sim) + 1),
        (uint32_t)(0x80000000ULL / sizeof(krb5_key_data_sim) + 1),
    };

    int num_values = sizeof(protocol_values) / sizeof(protocol_values[0]);

    for (int i = 0; i < num_values; i++) {
        uint32_t n_key_data_proto = protocol_values[i];
        size_t n_key_data = (size_t)n_key_data_proto;

        /* Security invariant: before any allocation, check must be performed */
        int would_overflow = (n_key_data > 0 &&
                              n_key_data > SIZE_MAX / sizeof(krb5_key_data_sim));

        if (would_overflow) {
            /* Must not allocate - safe_alloc must return NULL */
            void *ptr = safe_alloc_key_data(n_key_data);
            ck_assert_msg(ptr == NULL,
                "SECURITY VIOLATION: safe_alloc_key_data returned non-NULL "
                "for overflow-inducing n_key_data=%zu (proto value=0x%08X)",
                n_key_data, n_key_data_proto);
        } else if (n_key_data > 0) {
            /* Safe value - allocation may succeed or fail due to OOM */
            void *ptr = safe_alloc_key_data(n_key_data);
            if (ptr != NULL) {
                /* Verify the buffer is actually large enough */
                size_t alloc_size = n_key_data * sizeof(krb5_key_data_sim);
                ck_assert_msg(alloc_size / sizeof(krb5_key_data_sim) == n_key_data,
                    "SECURITY VIOLATION: Allocated buffer size calculation "
                    "inconsistent for n_key_data=%zu", n_key_data);
                free(ptr);
            }
        }
    }
}
END_TEST

START_TEST(test_multiplication_overflow_detection)
{
    /* Invariant: The overflow detection logic itself must be correct */

    struct {
        size_t count;
        size_t elem_size;
        int expect_overflow;
    } test_cases[] = {
        /* count, elem_size, expect_overflow */
        { SIZE_MAX, 1, 0 },                          /* No overflow: SIZE_MAX * 1 */
        { SIZE_MAX, 2, 1 },                          /* Overflow: SIZE_MAX * 2 */
        { SIZE_MAX / 2, 2, 0 },                      /* No overflow: (SIZE_MAX/2) * 2 */
        { SIZE_MAX / 2 + 1, 2, 1 },                  /* Overflow */
        { 0, sizeof(krb5_key_data_sim), 0 },         /* Zero count - no overflow */
        { 1, sizeof(krb5_key_data_sim), 0 },         /* One element - safe */
        { SIZE_MAX / sizeof(krb5_key_data_sim), sizeof(krb5_key_data_sim), 0 }, /* Boundary */
        { SIZE_MAX / sizeof(krb5_key_data_sim) + 1, sizeof(krb5_key_data_sim), 1 }, /* Just over */
    };

    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);

    for (int i = 0; i < num_cases; i++) {
        size_t count = test_cases[i].count;
        size_t elem_size = test_cases[i].elem_size;
        int expect_overflow = test_cases[i].expect_overflow;

        /* Overflow detection: count > SIZE_MAX / elem_size */
        int detected_overflow = (elem_size > 0 && count > SIZE_MAX / elem_size);

        ck_assert_msg(detected_overflow == expect_overflow,
            "Overflow detection mismatch for count=%zu, elem_size=%zu: "
            "expected_overflow=%d, detected=%d",
            count, elem_size, expect_overflow, detected_overflow);

        if (!detected_overflow && count > 0 && elem_size > 0) {
            /* Verify the multiplication is actually safe */
            size_t product = count * elem_size;
            ck_assert_msg(product / elem_size == count,
                "SECURITY VIOLATION: Multiplication overflow not detected "
                "for count=%zu, elem_size=%zu, product=%zu",
                count, elem_size, product);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security_KeyData_Allocation");
    tc_core = tcase_create("Core");

    tcase_set_timeout(tc_core, 30);
    tcase_add_test(tc_core, test_key_data_allocation_overflow);
    tcase_add_test(tc_core, test_key_data_count_validation);
    tcase_add_test(tc_core, test_multiplication_overflow_detection);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}