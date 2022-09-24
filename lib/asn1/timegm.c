/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "der_locl.h"

static int
is_leap(unsigned y)
{
    y += 1900;
    return (y % 4) == 0 && ((y % 100) != 0 || (y % 400) == 0);
}

static const unsigned ndays[2][12] ={
    {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
    {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}};

/*
 * This is a simplifed version of timegm(3) that doesn't accept out of
 * bound values that timegm(3) normally accepts but those are not
 * valid in asn1 encodings.
 *
 * X.680, section 46, GeneralizedTime, does not indicate that seconds are
 * 00..59, not 00..60, so it's not clear if leap seconds are meant to be
 * represented on the wire, but X.680, section 47, UTCTime, does.
 *
 * X.690, sections 11.7 and 11.8 do not cover the leap seconds matter either,
 * so it's not entirely clear that we need a timegm() wrapper...
 */

time_t
_der_timegm (struct tm *tm)
{
    int save_errno = errno;

    /*
     * If time_t is signed 32-bit, then we need to clamp any GeneralizedTime
     * dates past 2038 so we don't overflow when returning a time_t, and so we
     * don't have to fail.
     *
     * This became important when an implementation of Kerberos started sending
     * requested ticket end times in 9999-12-31!  Failing is not really an
     * option.
     *
     * We could make this
     *
     *  #if defined(TIME_T_SIGNED) && SIZEOF_TIME_T < 8
     *
     * but we really don't want to do that until we make sure that every place we
     * cast time_t to krb5_timestamp we do this clamping too.  Even then, making
     * krb5_timestamp a 64-bit integer will take a long time to do -- the best we
     * can do until then is make it unsigned and swap the year 2038 problem for a
     * year 2106 problem.
     *
     * Note that per-POSIX, tm_year 0 is 1900, and January is tm_mon value 0,
     * while tm_day starts at 1.
     */
    if (tm->tm_year > 138 ||
        (tm->tm_year == 138 &&
         (tm->tm_mon > 0 ||
          (tm->tm_mon == 0 &&
           (tm->tm_mday > 19 ||
            (tm->tm_mday == 19 &&
             (tm->tm_hour > 3 ||
              (tm->tm_hour == 3 &&
               (tm->tm_min > 14 ||
                (tm->tm_min == 14 &&
                 tm->tm_sec >= 7))))))))))
        return 2147483646; /* clamped to 2^31 - 2 */

    /*
     * We also clamp what would be negative values of time_t looking ahead to
     * treating time_t as unsigned on 32-bit systems or where we have 32-bit
     * time_t-like types (mainly krb5_timestamp).  Casting a negative time value
     * to an unsigned would be bad.
     */
    if (tm->tm_year < 0) {
        errno = ERANGE;
        return -1;
    }
    if (tm->tm_year < 70)
        return 1; /* clamped to 1 */

    /*
     * The C library's timegm() might normalize out of range tm field values like
     * mktime() would, but that's not interesting to us.
     */
    errno = ERANGE;
    if (tm->tm_mon < 0 || tm->tm_mon > 11)
        return -1;
    if (tm->tm_mday < 1 || tm->tm_mday > (int)ndays[is_leap(tm->tm_year)][tm->tm_mon])
        return -1;
    if (tm->tm_hour < 0 || tm->tm_hour > 23)
        return -1;
    if (tm->tm_min < 0 || tm->tm_min > 59)
        return -1;
    if (tm->tm_sec < 0 || tm->tm_sec > 60)
        return -1;
    errno = save_errno;

    /*
     * The C library's timegm() is better than anything we could build here, as
     * it takes into account leap seconds.  Though it should be easy enough to
     * hardcode a DB of leap seconds into lib/roken's rk_timegm(), and then we
     * could use that as it might be faster than the system C library's.  (At
     * least one C library implementation's timegm() takes and holds a mutex!)
     */
    return timegm(tm);
}

struct tm *
_der_gmtime(time_t t, struct tm *tm)
{
    /*
     * Should we clamp dates we send to match _der_timegm() above?  Probably
     * not.
     */
#ifdef WIN32
    return gmtime_s(tm, t) == 0 ? tm : NULL;
#else
    return gmtime_r(&t, tm);
#endif
}
