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

#include "baselocl.h"

static heim_base_atomic_type tidglobal = HEIM_TID_USER;

struct heim_base {
    heim_type_t isa;
    heim_base_atomic_type ref_cnt;
    uintptr_t isaextra[3]; 
};

/* specialized version of base */
struct heim_base_mem {
    heim_type_t isa;
    heim_base_atomic_type ref_cnt;
    const char *name;
    void (*dealloc)(void *);
    uintptr_t isaextra[1]; 
};

#define PTR2BASE(ptr) (((struct heim_base *)ptr) - 1)
#define BASE2PTR(ptr) ((void *)(((struct heim_base *)ptr) + 1))

/**
 * Retain object
 *
 * @param object to be released, NULL is ok
 *
 * @return the same object as passed in
 */

void *
heim_retain(void *ptr)
{
    struct heim_base *p = PTR2BASE(ptr);

    if (ptr == NULL || heim_base_is_tagged(ptr))
	return ptr;

    if (p->ref_cnt == heim_base_atomic_max)
	return ptr;

    if ((heim_base_atomic_inc(&p->ref_cnt) - 1) == 0)
	HEIM_BASE_ABORT("resurection");
    return ptr;
}

/**
 * Release object, free is reference count reaches zero
 *
 * @param object to be released
 */

void
heim_release(void *ptr)
{
    heim_base_atomic_type old;
    struct heim_base *p = PTR2BASE(ptr);

    if (ptr == NULL || heim_base_is_tagged(ptr))
	return;

    if (p->ref_cnt == heim_base_atomic_max)
	return;

    old = heim_base_atomic_dec(&p->ref_cnt) + 1;

    if (old > 1)
	return;

    if (old == 1) {
	if (p->isa->dealloc)
	    p->isa->dealloc(ptr);
	free(p);
    } else
	HEIM_BASE_ABORT("over release");
}

static heim_type_t tagged_isa[9] = {
    &_heim_number_object,
    &_heim_null_object,
    &_heim_bool_object,

    NULL,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL
};

heim_type_t
_heim_get_isa(heim_object_t ptr)
{
    struct heim_base *p;
    if (heim_base_is_tagged(ptr)) {
	if (heim_base_is_tagged_object(ptr))
	    return tagged_isa[heim_base_tagged_object_tid(ptr)];
	if (heim_base_is_tagged_string(ptr))
	    return &_heim_string_object;
	abort();
    }
    p = PTR2BASE(ptr);
    return p->isa;
}

/**
 * Get type ID of object
 *
 * @param object object to get type id of
 *
 * @return type id of object
 */

heim_tid_t
heim_get_tid(heim_object_t ptr)
{
    heim_type_t isa = _heim_get_isa(ptr);
    return isa->tid;
}

/**
 * Get hash value of object
 *
 * @param object object to get hash value for
 *
 * @return a hash value
 */

unsigned long
heim_get_hash(heim_object_t ptr)
{
    heim_type_t isa = _heim_get_isa(ptr);
    if (isa->hash)
	return isa->hash(ptr);
    return (unsigned long)ptr;
}

/**
 * Compare two objects, returns 0 if equal, can use used for qsort()
 * and friends.
 *
 * @param a first object to compare
 * @param b first object to compare
 *
 * @return 0 if objects are equal
 */

int
heim_cmp(heim_object_t a, heim_object_t b)
{
    heim_tid_t ta, tb;
    heim_type_t isa;
 
    ta = heim_get_tid(a);
    tb = heim_get_tid(b);

    if (ta != tb)
	return ta - tb;

    isa = _heim_get_isa(a);

    if (isa->cmp)
	return isa->cmp(a, b);

    return (uintptr_t)a - (uintptr_t)b;
}

/*
 * Private - allocates an memory object
 */

static void
memory_dealloc(void *ptr)
{
    struct heim_base_mem *p = (struct heim_base_mem *)PTR2BASE(ptr);
    if (p->dealloc)
	p->dealloc(ptr);
}

struct heim_type_data memory_object = {
    HEIM_TID_MEMORY,
    "memory-object",
    NULL,
    memory_dealloc,
    NULL,
    NULL,
    NULL
};

void *
heim_alloc(size_t size, const char *name, heim_type_dealloc dealloc)
{
    /* XXX use posix_memalign */

    struct heim_base_mem *p = calloc(1, size + sizeof(*p));
    if (p == NULL)
	return NULL;
    p->isa = &memory_object;
    p->ref_cnt = 1;
    p->name = name;
    p->dealloc = dealloc;
    return BASE2PTR(p);
}

heim_type_t
_heim_create_type(const char *name,
		  heim_type_init init,
		  heim_type_dealloc dealloc,
		  heim_type_copy copy,
		  heim_type_cmp cmp,
		  heim_type_hash hash)
{
    heim_type_t type;

    /* XXX posix_memalign */

    type = calloc(1, sizeof(*type));
    if (type == NULL)
	return NULL;

    type->tid = heim_base_atomic_inc(&tidglobal);
    type->name = name;
    type->init = init;
    type->dealloc = dealloc;
    type->copy = copy;
    type->cmp = cmp;
    type->hash = hash;

    return type;
}

heim_object_t
_heim_alloc_object(heim_type_t type, size_t size)
{
    struct heim_base *p = calloc(1, size + sizeof(*p));
    if (p == NULL)
	return NULL;
    p->isa = type;
    p->ref_cnt = 1;

    return BASE2PTR(p);
}

heim_tid_t
_heim_type_get_tid(heim_type_t type)
{
    return type->tid;
}

/**
 * Call func once and only once
 *
 * @param once pointer to a heim_base_once_t
 * @param ctx context passed to func
 * @param func function to be called
 */

void
heim_base_once_f(heim_base_once_t *once, void *ctx, void (*func)(void *))
{
#ifdef HAVE_DISPATCH_DISPATCH_H
    dispatch_once_f(once, ctx, func);
#else
    #error "write heim_base_once_t"
#endif
}
