/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/gss_utils.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

#ifndef TEST_SEQ_NUMS
static OM_uint32
_gss_copy_oid(OM_uint32 *minor_status,
	      gss_const_OID from_oid,
	      gss_OID to_oid)
{
	size_t len = from_oid->length;

	*minor_status = 0;
	to_oid->elements = malloc(len);
	if (!to_oid->elements) {
		to_oid->length = 0;
		*minor_status = ENOMEM;
		return GSS_S_FAILURE;
	}
	to_oid->length = (OM_uint32)len;
	memcpy(to_oid->elements, from_oid->elements, len);
	return (GSS_S_COMPLETE);
}

OM_uint32
_gss_free_oid(OM_uint32 *minor_status, gss_OID oid)
{
	*minor_status = 0;
	if (oid->elements) {
	    free(oid->elements);
	    oid->elements = NULL;
	    oid->length = 0;
	}
	return (GSS_S_COMPLETE);
}

struct _gss_interned_oid {
    HEIM_SLIST_ATOMIC_ENTRY(_gss_interned_oid) gio_link;
    gss_OID_desc gio_oid;
};

static HEIM_SLIST_ATOMIC_HEAD(_gss_interned_oid_list, _gss_interned_oid) interned_oids =
HEIM_SLIST_HEAD_INITIALIZER(interned_oids);

extern gss_OID _gss_ot_internal[];
extern size_t _gss_ot_internal_count;

static OM_uint32
intern_oid_static(OM_uint32 *minor_status,
		  gss_const_OID from_oid,
		  gss_OID *to_oid)
{
    size_t i;

    /* statically allocated OIDs */
    for (i = 0; i < _gss_ot_internal_count; i++) {
	if (gss_oid_equal(_gss_ot_internal[i], from_oid)) {
	    *minor_status = 0;
	    *to_oid = _gss_ot_internal[i];
	    return GSS_S_COMPLETE;
	}
    }

    return GSS_S_CONTINUE_NEEDED;
}

OM_uint32
_gss_intern_oid(OM_uint32 *minor_status,
		gss_const_OID from_oid,
		gss_OID *to_oid)
{
    OM_uint32 major_status;
    struct _gss_interned_oid *iop;

    major_status = intern_oid_static(minor_status, from_oid, to_oid);
    if (major_status != GSS_S_CONTINUE_NEEDED)
	return major_status;

    HEIM_SLIST_ATOMIC_FOREACH(iop, &interned_oids, gio_link) {
	if (gss_oid_equal(&iop->gio_oid, from_oid)) {
	    *minor_status = 0;
	    *to_oid = &iop->gio_oid;
	    return GSS_S_COMPLETE;
	}
    }

    iop = malloc(sizeof(*iop));
    if (iop == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    major_status = _gss_copy_oid(minor_status, from_oid, &iop->gio_oid);
    if (GSS_ERROR(major_status)) {
	free(iop);
	return major_status;
    }

    HEIM_SLIST_ATOMIC_INSERT_HEAD(&interned_oids, iop, gio_link);

    *minor_status = 0;
    *to_oid = &iop->gio_oid;

    return GSS_S_COMPLETE;
}

OM_uint32
_gss_copy_buffer(OM_uint32 *minor_status,
    const gss_buffer_t from_buf, gss_buffer_t to_buf)
{
	size_t len = from_buf->length;

	*minor_status = 0;
	to_buf->value = malloc(len);
	if (!to_buf->value) {
		*minor_status = ENOMEM;
		to_buf->length = 0;
		return GSS_S_FAILURE;
	}
	to_buf->length = len;
	memcpy(to_buf->value, from_buf->value, len);
	return (GSS_S_COMPLETE);
}

OM_uint32
_gss_secure_release_buffer(OM_uint32 *minor_status,
			   gss_buffer_t buffer)
{
    if (buffer->value)
	memset_s(buffer->value, buffer->length, 0, buffer->length);

    return gss_release_buffer(minor_status, buffer);
}

OM_uint32
_gss_secure_release_buffer_set(OM_uint32 *minor_status,
			       gss_buffer_set_t *buffer_set)
{
    size_t i;
    OM_uint32 minor;

    *minor_status = 0;

    if (*buffer_set == GSS_C_NO_BUFFER_SET)
	return GSS_S_COMPLETE;

    for (i = 0; i < (*buffer_set)->count; i++)
	_gss_secure_release_buffer(&minor, &((*buffer_set)->elements[i]));

    (*buffer_set)->count = 0;

    return gss_release_buffer_set(minor_status, buffer_set);
}

void
_gss_mg_encode_le_uint64(uint64_t n, uint8_t *p)
{
    p[0] = (n >> 0 ) & 0xFF;
    p[1] = (n >> 8 ) & 0xFF;
    p[2] = (n >> 16) & 0xFF;
    p[3] = (n >> 24) & 0xFF;
    p[4] = (n >> 32) & 0xFF;
    p[5] = (n >> 40) & 0xFF;
    p[6] = (n >> 48) & 0xFF;
    p[7] = (n >> 56) & 0xFF;
}

void
_gss_mg_decode_le_uint64(const void *ptr, uint64_t *n)
{
    const uint8_t *p = ptr;
    *n = ((uint64_t)p[0] << 0)
       | ((uint64_t)p[1] << 8)
       | ((uint64_t)p[2] << 16)
       | ((uint64_t)p[3] << 24)
       | ((uint64_t)p[4] << 32)
       | ((uint64_t)p[5] << 40)
       | ((uint64_t)p[6] << 48)
       | ((uint64_t)p[7] << 56);
}

void
_gss_mg_encode_be_uint64(uint64_t n, uint8_t *p)
{
    p[0] = (n >> 56) & 0xFF;
    p[1] = (n >> 48) & 0xFF;
    p[2] = (n >> 40) & 0xFF;
    p[3] = (n >> 32) & 0xFF;
    p[4] = (n >> 24) & 0xFF;
    p[5] = (n >> 16) & 0xFF;
    p[6] = (n >> 8 ) & 0xFF;
    p[7] = (n >> 0 ) & 0xFF;
}

void
_gss_mg_decode_be_uint64(const void *ptr, uint64_t *n)
{
    const uint8_t *p = ptr;
    *n = ((uint64_t)p[0] << 56)
       | ((uint64_t)p[1] << 48)
       | ((uint64_t)p[2] << 40)
       | ((uint64_t)p[3] << 32)
       | ((uint64_t)p[4] << 24)
       | ((uint64_t)p[5] << 16)
       | ((uint64_t)p[6] << 8)
       | ((uint64_t)p[7] << 0);
}

void
_gss_mg_encode_le_uint32(uint32_t n, uint8_t *p)
{
    p[0] = (n >> 0 ) & 0xFF;
    p[1] = (n >> 8 ) & 0xFF;
    p[2] = (n >> 16) & 0xFF;
    p[3] = (n >> 24) & 0xFF;
}

void
_gss_mg_decode_le_uint32(const void *ptr, uint32_t *n)
{
    const uint8_t *p = ptr;
    *n = ((uint32_t)p[0] << 0)
       | ((uint32_t)p[1] << 8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

void
_gss_mg_encode_be_uint32(uint32_t n, uint8_t *p)
{
    p[0] = (n >> 24) & 0xFF;
    p[1] = (n >> 16) & 0xFF;
    p[2] = (n >> 8 ) & 0xFF;
    p[3] = (n >> 0 ) & 0xFF;
}

void
_gss_mg_decode_be_uint32(const void *ptr, uint32_t *n)
{
    const uint8_t *p = ptr;
    *n = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | (p[3] << 0);
}

void
_gss_mg_encode_le_uint16(uint16_t n, uint8_t *p)
{
    p[0] = (n >> 0 ) & 0xFF;
    p[1] = (n >> 8 ) & 0xFF;
}

void
_gss_mg_decode_le_uint16(const void *ptr, uint16_t *n)
{
    const uint8_t *p = ptr;
    *n = (p[0] << 0) | (p[1] << 8);
}

void
_gss_mg_encode_be_uint16(uint16_t n, uint8_t *p)
{
    p[0] = (n >> 8) & 0xFF;
    p[1] = (n >> 0) & 0xFF;
}

void
_gss_mg_decode_be_uint16(const void *ptr, uint16_t *n)
{
    const uint8_t *p = ptr;
    *n = (p[0] << 24) | (p[1] << 16);
}

OM_uint32
_gss_mg_ret_oid(OM_uint32 *minor,
		krb5_storage *sp,
		gss_OID *oidp)
{
    krb5_data data;
    gss_OID_desc oid;
    OM_uint32 major;

    *minor = 0;
    *oidp = GSS_C_NO_OID;

    *minor = krb5_ret_data(sp, &data);
    if (*minor)
        return GSS_S_FAILURE;

    if (data.length) {
        oid.length = data.length;
        oid.elements = data.data;

        major = _gss_intern_oid(minor, &oid, oidp);
    } else
        major = GSS_S_COMPLETE;

    krb5_data_free(&data);

    return major;
}

OM_uint32
_gss_mg_store_oid(OM_uint32 *minor,
		  krb5_storage *sp,
		  gss_const_OID oid)
{
    krb5_data data;

    if (oid) {
        data.length = oid->length;
        data.data = oid->elements;
    } else
	krb5_data_zero(&data);

    *minor = krb5_store_data(sp, data);

    return *minor ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

OM_uint32
_gss_mg_ret_buffer(OM_uint32 *minor,
		   krb5_storage *sp,
		   gss_buffer_t buffer)
{
    krb5_data data;

    _mg_buffer_zero(buffer);

    *minor = krb5_ret_data(sp, &data);
    if (*minor == 0) {
	if (data.length) {
	    buffer->length = data.length;
	    buffer->value = data.data;
	} else
	    krb5_data_free(&data);
    }

    return *minor ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

OM_uint32
_gss_mg_store_buffer(OM_uint32 *minor,
		     krb5_storage *sp,
		     gss_const_buffer_t buffer)
{
    krb5_data data;

    if (buffer) {
        data.length = buffer->length;
        data.data = buffer->value;
    } else
	krb5_data_zero(&data);

    *minor =  krb5_store_data(sp, data);

    return *minor ? GSS_S_FAILURE : GSS_S_COMPLETE;
}
#endif

/*
 * Check if `sn' is in the window `win', which supports only 32 sequence
 * numbers in the window.
 *
 * Here the window has an odd seqnum that is the center of a 32-bit bitmask of
 * sequence numbers, and which mask is paired with the low 32 bits of said
 * center seqnum:
 *
 *     +----------------------------------------------+
 *     | uint64_t center_seqnum (15, 31, 47, 63, ...) |
 *     | uint64_t mask                                |
 *     |       +-----------------------------------+  |
 *     |       | center >>4 & 2^32-1 | 32-bit mask |  |
 *     |       |     __ __ __ __     | __ __ __ __ |  |
 *     |       +-----------------------------------+  |
 *     +----------------------------------------------+
 *
 * Our task is to see if `sn' is too old, to maybe slide the window (replace
 * `center_seqnum') if `sn - center_seqnum > 16' and re-write the mask, to set a
 * bit in the 32-bit mask if we don't rewrite the mask.
 *
 * We use two atomic operations for this: a CAS to replace the `center_seqnum'
 * (if need be) and a CAS to replace the `mask'.  Note that replacing the
 * `center_seqnum' can implicitly slide the mask by 16 bits or even invalidate
 * it altogether.  We use 32 bits of the `center_seqnum' to help with mask
 * invalidation and recovery from mask invalidation.
 */
OM_uint32
_gss_rcv_seqnum_check1(uint64_t sn, struct seqnum_window *win)
{
    uint64_t oldcenter, noo, oldmask, noomask;
    uint32_t sn_lsb = ((sn >> 4) & ~UINT32_MAX);
    size_t bit;
    size_t i = 3;

    oldcenter = heim_base_atomic_load(&win->center_seqnum);
    if (oldcenter == 0) {
        /* Win or lose, we win */
        (void) heim_base_cas_64(&win->center_seqnum, oldcenter, 15);
        oldcenter = heim_base_atomic_load(&win->center_seqnum);
    }

    /* Check invariants.  Mainly that `(win->center_seqnum & 15) == 15' */
    if ((oldcenter & 15) != 15)
        return GSS_S_FAILURE;

    /* Check if this is a very old or very new token */
    if (sn < oldcenter - 15)
        return GSS_S_OLD_TOKEN; /* Fell out of the window */

    /* Check how many times we're willing to race to CAS win->center_seqnum */
    if (sn > oldcenter + 16)
        i = ((sn & ~15) - (oldcenter + 1)) >> 4; /* Want to slide window */

    /* While `sn' is far enough ahead of `win->center_seqnum' */
    for (oldcenter = heim_base_atomic_load(&win->center_seqnum);
         i && sn > oldcenter + 16;
         i--, oldcenter = heim_base_atomic_load(&win->center_seqnum)) {

        if ((sn & ~15) <= oldcenter + 16)
            break; /* In the window now */

        /* Slide window forward */
        noo = (sn & ~15) - 1;
        if (heim_base_cas_64(&win->center_seqnum, oldcenter, noo))
            break;
    }

    if (sn < oldcenter - 15)
        return GSS_S_OLD_TOKEN; /* Fell out of the window */
    if (i == 0)
        /*
         * This shouldn't happen.  We can't lose the race to CAS
         * win->center_seqnum so many times and not find that our sequence
         * number is now too old, so it must just be very new (far into the
         * future space of the sequence number window) and other threads are
         * winning the race with less-new sequence numbers.  After all, we set
         * the number of go arounds in the loop to the number of half-windows
         * `sn' is ahead of `win->center_seqnum`!
         *
         * So this return should be dead code.
         */
        return GSS_S_FAILURE;

    /*
     * We now need to:
     *
     *  - check for mask invalidation
     *  - check and set the bit corresponding to `sn'
     *
     * We use an atomic CAS to set the `bit' in the `win->mask[0]'.  The CAS can
     * fail and need to be retried.  Since there are only 32 bits in the mask,
     * we need not try the CAS more than 32 times, so our loop has a hard
     * bound.
     */
    /* `bit' is a bit in whichever half of the 32-bit mask it belongs to */
    bit = 1ULL << (sn & 15);
    for (i = 0; i < 32; i++) {
        uint32_t mask_sn_lsb;

        oldmask = heim_base_atomic_load(&win->masks[0]);
        mask_sn_lsb = (oldmask >> 4) & UINT32_MAX;

        if (mask_sn_lsb > sn_lsb)
            /*
             * While we've been looping, the window slid forward enough to make
             * `sn' old.
             */
            return GSS_S_OLD_TOKEN;

        if (mask_sn_lsb == sn_lsb && sn > oldcenter) {
            if (sn > oldcenter)
                /*
                 * We want to set the `bit' in the high 16-bit half of the
                 * 32-bit mask half of `win->masks[0]'.  No need to slide the
                 * mask.
                 */
                bit <<= 1;
            /* else we want to set the `bit' in the low half of... */

            noomask = oldmask | bit;
        } else if (sn_lsb && mask_sn_lsb == sn_lsb + 1) {
            /* We need to slide the mask */
            noomask = (((uint64_t)sn_lsb) << 32) | ((oldmask & UINT32_MAX) >> 16);
        } else {
            /* Brand new mask */
            noomask = (((uint64_t)sn_lsb) << 32) | bit;
        }
        if (oldmask & bit)
            return GSS_S_DUPLICATE_TOKEN;

        /* Finally, CAS the new mask into place */
        if (!heim_base_cas_64(&win->masks[0], oldmask, noomask))
            continue;

        /* Returns only in the rest of this loop */

        /* Decide if GAP or UNSEQ token or neither */
        if ((oldmask & ((uint64_t)UINT32_MAX)) > bit)
            return GSS_S_GAP_TOKEN;
        if ((oldmask & ((uint64_t)UINT32_MAX)) < (bit>>1))
            return GSS_S_UNSEQ_TOKEN;
        return GSS_S_COMPLETE;
    }
    /*
     * If we tried 32 times to set the bit and failed, then we must have lost a
     * race with a thread that slid the window forward, making this sequence
     * number too old now.
     *
     * XXX We almost certainly need to go around a few more times to be
     * certain, since maybe we're setting one of the upper 16 bits and then
     * that's now in the lower 16 bits.
     */
    return GSS_S_OLD_TOKEN;
}

#if 0
/*
 * Check if `sn' is in the window `win', which has `1ULL<<mshift' masks of 32
 * sequence numbers.  Generalizes _gss_rcv_seqnum_check1() so as to have more
 * than 32 sequence numbers in the window.
 *
 * XXX Implement?
 *
 * Generalizing the window sliding should be easy, maybe maybe maybe.
 */
OM_uint32
_gss_rcv_seqnum_checkN(uint64_t sn, struct seqnum_window *win, int8_t mshift)
{
}
#endif

#ifdef TEST_SEQ_NUMS
#include <inttypes.h>
#include <gsskrb5_locl.h>
#include <getarg.h>
int version_flag;
int help_flag;
static struct getargs args[] = {
    { "version", 0, arg_flag, &version_flag, NULL, NULL },
    { "help", 'h', arg_flag, &help_flag, NULL, NULL }
};

int
main(int argc, char **argv)
{
    struct seqnum_window win;
    size_t linesz = 0;
    char *line = NULL;
    int optidx;

    win.center_seqnum = 0;
    win.masks[0] = 0;

    if (getarg(args, sizeof(args)/sizeof(args[0]), argc, argv, &optidx)) {
        fprintf(stderr, "Usage: test_seqnums [FILE]\n");
        exit(1);
    }
    if (version_flag) {
        print_version(NULL);
        exit(0);
    }
    if (help_flag) {
        printf("Usage: test_seqnums [FILE]\n"
               "    Inputs to this program are of the following form:\n"
               "        NUMBER (a received sequence number)\n"
               "        show   (shows the state of the received window)\n"
               "        reset  (resets the received window state to\n"
               "                empty starting at 0)\n");
        return 0;
    }

    argc -= optidx;
    argv += optidx;

    if (argc > 1)
        errx(1, "Too many arguments");
    if (argc) {
        if (freopen(argv[0], "rb", stdin) == NULL)
            err(1, "Could not open %s", argv[0]);
    }
    while (getline(&line, &linesz, stdin) > -1) {
        uint64_t seqnum = 0;

        if (strcmp(line, "show\n") == 0) {
            printf("window: %"PRIu64" %"PRIx64"\n", win.center_seqnum, win.masks[0]);
        } else if (strcmp(line, "reset\n") == 0) {
            win.center_seqnum = 0;
            win.masks[0] = 0;
        } else if (sscanf(line, "%"SCNu64, &seqnum) == 1) {
            OM_uint32 maj;
            switch ((maj = _gss_rcv_seqnum_check1(seqnum, &win))) {
            case GSS_S_FAILURE:
                printf("%"PRIu64"\tFAIL\n", seqnum);
                break;
            case GSS_S_DUPLICATE_TOKEN:
                printf("%"PRIu64"\tDUP\n", seqnum);
                break;
            case GSS_S_OLD_TOKEN:
                printf("%"PRIu64"\tOLD\n", seqnum);
                break;
            case GSS_S_GAP_TOKEN:
                printf("%"PRIu64"\tGAP\n", seqnum);
                break;
            case GSS_S_UNSEQ_TOKEN:
                printf("%"PRIu64"\tUNSEQ\n", seqnum);
                break;
            case GSS_S_COMPLETE:
                printf("%"PRIu64"\tCOMPLETE\n", seqnum);
                break;
            default:
                errx(1, "Unexpected result: %u", maj);
            }
        } else {
            errx(1, "Did not expect input: %s", line);
        }
    }
    return 0;
}
#endif
