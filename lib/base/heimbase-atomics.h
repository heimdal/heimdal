/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
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

#ifndef HEIM_BASE_ATOMICS_H
#define HEIM_BASE_ATOMICS_H 1

#include "config.h"

/*
 * Atomic operations
 */

#if defined(HAVE_STDATOMIC_H)

#include <stdatomic.h>

#define heim_base_atomic_init(t, v)	atomic_init(t, v)
#define heim_base_atomic_load(x)	atomic_load((x))
#define heim_base_atomic_store(t, v)	atomic_store((t), (v))

#define heim_base_atomic(T)		_Atomic(T)

#define heim_base_atomic_inc(x)		(atomic_fetch_add((x), 1) + 1)
#define heim_base_atomic_dec(x)		(atomic_fetch_sub((x), 1) - 1)
#define heim_base_atomic_integer_type	heim_base_atomic(unsigned int)
#define heim_base_atomic_integer_max	UINT_MAX

#define heim_base_exchange_pointer(t,v) atomic_exchange((t), (v))
#define heim_base_exchange_32(t,v)	atomic_exchange((t), (v))
#define heim_base_exchange_64(t,v)	atomic_exchange((t), (v))

#elif defined(__GNUC__) && defined(HAVE___SYNC_ADD_AND_FETCH)

#define heim_base_atomic_barrier()	__sync_synchronize()

#define heim_base_atomic_inc(x)		__sync_add_and_fetch((x), 1)
#define heim_base_atomic_dec(x)		__sync_sub_and_fetch((x), 1)
#define heim_base_atomic_integer_type	unsigned int
#define heim_base_atomic_integer_max	UINT_MAX

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if __has_builtin(__sync_swap)
#define heim_base_exchange_pointer(t,v) __sync_swap((t), (v))
#else
/* FIXME: some targets may only write the value 1 into *t */
#define heim_base_exchange_pointer(t,v) __sync_lock_test_and_set((t), (v))
#endif

#define heim_base_exchange_32(t,v)	heim_base_exchange_pointer((t), (v))
#define heim_base_exchange_64(t,v)	heim_base_exchange_pointer((t), (v))

#elif defined(__sun)

#include <sys/atomic.h>

#define heim_base_atomic_barrier()	__machine_rw_barrier()

#define heim_base_atomic_inc(x)		atomic_inc_uint_nv((volatile uint_t *)(x))
#define heim_base_atomic_dec(x)		atomic_dec_uint_nv((volatile uint_t *)(x))
#define heim_base_atomic_integer_type	uint_t
#define heim_base_atomic_integer_max	UINT_MAX

#define heim_base_exchange_pointer(t,v) atomic_swap_ptr((volatile void *)(t), (void *)(v))
#define heim_base_exchange_32(t,v)	atomic_swap_32((volatile uint32_t *)(t), (v))
#define heim_base_exchange_64(t,v)	atomic_swap_64((volatile uint64_t *)(t), (v))

#elif defined(_AIX)

#include <sys/atomic_op.h>

#define heim_base_atomic_barrier()	__isync()

#define heim_base_atomic_inc(x)		(fetch_and_add((atomic_p)(x)) + 1)
#define heim_base_atomic_dec(x)		(fetch_and_add((atomic_p)(x)) - 1)
#define heim_base_atomic_integer_type	unsigned int
#define heim_base_atomic_integer_max	UINT_MAX

static inline void *
heim_base_exchange_pointer(void *p, void *newval)
{
    void *val = *(void **)p;

    while (!compare_and_swaplp((atomic_l)p, (long *)&val, (long)newval))
        ;

    return val;
}

static inline uint32_t
heim_base_exchange_32(uint32_t *p, uint32_t newval)
{
    uint32_t val = *p;

    while (!compare_and_swap((atomic_p)p, (int *)&val, (int)newval))
        ;

    return val;
}

static inline uint64_t
heim_base_exchange_64(uint64_t *p, uint64_t newval)
{
    uint64_t val = *p;

    while (!compare_and_swaplp((atomic_l)p, (long *)&val, (long)newval))
        ;

    return val;
}

#elif defined(_WIN32)

#define heim_base_atomic_barrier()	MemoryBarrier()

#define heim_base_atomic_inc(x)		InterlockedIncrement(x)
#define heim_base_atomic_dec(x)		InterlockedDecrement(x)
#define heim_base_atomic_integer_type	LONG
#define heim_base_atomic_integer_max	MAXLONG

#define heim_base_exchange_pointer(t,v) InterlockedExchangePointer((PVOID volatile *)(t), (PVOID)(v))
#define heim_base_exchange_32(t,v)	((ULONG)InterlockedExchange((LONG volatile *)(t), (LONG)(v)))
#define heim_base_exchange_64(t,v)	((ULONG64)InterlockedExchange64((LONG64 violatile *)(t), (LONG64)(v)))

#else

#include <heim_threads.h>

#define HEIM_BASE_NEED_ATOMIC_MUTEX 1
extern HEIMDAL_MUTEX _heim_base_mutex;

#define heim_base_atomic_integer_type	unsigned int
#define heim_base_atomic_integer_max	UINT_MAX

static inline heim_base_atomic_integer_type
heim_base_atomic_inc(heim_base_atomic_integer_type *x)
{
    heim_base_atomic_integer_type t;
    HEIMDAL_MUTEX_lock(&_heim_base_mutex);
    t = ++(*x);
    HEIMDAL_MUTEX_unlock(&_heim_base_mutex);
    return t;
}

static inline heim_base_atomic_integer_type
heim_base_atomic_dec(heim_base_atomic_integer_type *x)
{
    heim_base_atomic_integer_type t;
    HEIMDAL_MUTEX_lock(&_heim_base_mutex);
    t = --(*x);
    HEIMDAL_MUTEX_unlock(&_heim_base_mutex);
    return t;
}

static inline void *
heim_base_exchange_pointer(void *target, void *value)
{
    void *old;
    HEIMDAL_MUTEX_lock(&_heim_base_mutex);
    old = *(void **)target;
    *(void **)target = value;
    HEIMDAL_MUTEX_unlock(&_heim_base_mutex);
    return old;
}

static inline uint32_t
heim_base_exchange_32(uint32_t *p, uint32_t newval)
{
    uint32_t old;
    HEIMDAL_MUTEX_lock(&_heim_base_mutex);
    old = *p;
    *p = newval;
    HEIMDAL_MUTEX_unlock(&_heim_base_mutex);
    return old;
}

static inline uint64_t
heim_base_exchange_64(uint64_t *p, uint64_t newval)
{
    uint64_t old;
    HEIMDAL_MUTEX_lock(&_heim_base_mutex);
    old = *p;
    *p = newval;
    HEIMDAL_MUTEX_unlock(&_heim_base_mutex);
    return old;
}

#endif /* defined(__GNUC__) && defined(HAVE___SYNC_ADD_AND_FETCH) */

#ifndef heim_base_atomic
#define heim_base_atomic(T)		T
#endif

#ifndef heim_base_atomic_barrier
#define heim_base_atomic_barrier()
#endif

#ifndef heim_base_atomic_load
#define heim_base_atomic_load(x)	(heim_base_atomic_barrier(), *(x))
#endif

#ifndef heim_base_atomic_init
#define heim_base_atomic_init(t, v)	do { (*(t) = (v)); } while (0)
#endif

#ifndef heim_base_atomic_store
#define heim_base_atomic_store(t, v)	do {					\
					    (*(t) = (v));			\
					    heim_base_atomic_barrier();		\
					} while (0)
#endif

#if SIZEOF_TIME_T == 8
#define heim_base_exchange_time_t(t,v)	heim_base_exchange_64((t), (v))
#elif SIZEOF_TIME_T == 4
#define heim_base_exchange_time_t(t,v)	heim_base_exchange_32((t), (v))
#else
#error set SIZEOF_TIME_T for your platform
#endif

#endif /* HEIM_BASE_ATOMICS_H */
