/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
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

/*
 * Timeval stuff
 */

#include <config.h>

#include "roken.h"

ROKEN_LIB_FUNCTION time_t ROKEN_LIB_CALL
rk_time_add(time_t t, time_t delta)
{
    if (delta == 0)
        return t;

#ifdef TIME_T_SIGNED
    /* Signed overflow is UB in C */
#if SIZEOF_TIME_T == 4
    if (t >= 0 && delta > 0 && INT32_MAX - t < delta)
        /* Time left to hit INT32_MAX is less than what we want to add */
        return INT32_MAX;
    else if (t < 0 && delta == INT32_MIN)
        /* Avoid computing -delta when t == INT32_MIN! */
        return INT32_MIN;
    else if (t == INT32_MIN && delta < 0)
        /* Avoid computing -t when t == INT32_MIN! */
        return INT32_MIN;
    else if (t < 0 && delta < 0 && INT32_MIN + (-t) < (-delta))
        /* Time left to hit INT32_MIN is less than what we want to subtract */
        return INT32_MIN;
    else
        return t + delta;
#elif SIZEOF_TIME_T == 8
    if (t >= 0 && delta > 0 && INT64_MAX - t < delta)
        return INT64_MAX;
    else if (t < 0 && delta == INT64_MIN)
        /* Avoid computing -delta when t == INT64_MIN! */
        return INT64_MIN;
    else if (t == INT64_MIN && delta < 0)
        /* Avoid computing -t when t == INT64_MIN! */
        return INT64_MIN;
    else if (t < 0 && delta < 0 && INT64_MIN + (-t) < (-delta))
        return INT64_MIN;
    else
        return t + delta;
#else
#error "Unexpected sizeof(time_t)"
#endif
#else

    /* Unsigned overflow is defined in C */
#if SIZEOF_TIME_T == 4
    if (t + delta < t)
        return UINT32_MAX;
#elif SIZEOF_TIME_T == 8
    if (t + delta < t)
        return UINT64_MAX;
#else
#error "Unexpected sizeof(time_t)"
#endif
#endif
    return t + delta;
}

ROKEN_LIB_FUNCTION time_t ROKEN_LIB_CALL
rk_time_sub(time_t t, time_t delta)
{
    if (delta == 0)
        return t;
#ifdef TIME_T_SIGNED
    if (delta > 0)
        return rk_time_add(t, -delta);
#if SIZEOF_TIME_T == 4
    if (delta == INT32_MIN) {
        if (t < 0) {
            t = t + INT32_MAX;
            return t + 1;
        }
        return INT32_MAX;
    }
    /* Safe to compute -delta, so use rk_time_add() to add -delta */
    return rk_time_add(t, -delta);
#elif SIZEOF_TIME_T == 8
    if (delta == INT64_MIN) {
        if (t < 0) {
            t = t + INT64_MAX;
            return t + 1;
        }
        return INT64_MAX;
    }
    return rk_time_add(t, -delta);
#else
#error "Unexpected sizeof(time_t)"
#endif
#else
    /* Both t and delta are non-negative. */
    if (delta > t)
        return 0;
#endif
    return t - delta;
}

/*
 * Make `t1' consistent.
 */

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
timevalfix(struct timeval *t1)
{
    if (t1->tv_usec < 0) {
        t1->tv_sec = rk_time_sub(t1->tv_sec, 1);
        t1->tv_usec = 1000000;
    }
    if (t1->tv_usec >= 1000000) {
        t1->tv_sec = rk_time_add(t1->tv_sec, 1);
        t1->tv_usec -= 1000000;
    }
}

/*
 * t1 += t2
 */

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
timevaladd(struct timeval *t1, const struct timeval *t2)
{
    t1->tv_sec   = rk_time_add(t1->tv_sec, t2->tv_sec);
    t1->tv_usec += t2->tv_usec;
    timevalfix(t1);
}

/*
 * t1 -= t2
 */

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
timevalsub(struct timeval *t1, const struct timeval *t2)
{
    t1->tv_sec   = rk_time_sub(t1->tv_sec, t2->tv_sec);
    t1->tv_usec -= t2->tv_usec;
    timevalfix(t1);
}
