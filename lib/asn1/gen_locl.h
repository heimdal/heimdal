/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
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

/* $Id$ */

#ifndef __GEN_LOCL_H__
#define __GEN_LOCL_H__

#include <config.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <err.h>
#include <roken.h>
#include <getarg.h>
#include "gen_module.h"
#include "hash.h"
#include "symbol.h"
#include "asn1-common.h"
#include "der.h"
#include "der-private.h"

void generate_types(asn1_module);
void c_generate_type (asn1_module, const Symbol *);
void c_generate_type_header_forwards(asn1_module, const Symbol *);
void c_generate_constant (asn1_module, const Symbol *);
void c_generate_type_encode (asn1_module, const Symbol *);
void c_generate_type_decode (asn1_module, const Symbol *);
void c_generate_type_free (asn1_module, const Symbol *);
void c_generate_type_length (asn1_module, const Symbol *);
void c_generate_type_print_stub(asn1_module, const Symbol *);
void c_generate_type_copy (asn1_module, const Symbol *);
void c_generate_type_seq (asn1_module, const Symbol *);
void c_generate_glue (asn1_module, const Type *, const char*);

const char *classname(Der_class);
const char *valuename(Der_class, int);

void c_gen_compare_defval(asn1_module, const char *, struct value *);
void c_gen_assign_defval(asn1_module, const char *, struct value *);

int objid_cmp(struct objid *, struct objid *);

void c_init_generate (asn1_module, const char *, const char *);
const char *get_filename (asn1_module);
void close_generate(asn1_module am);
void c_add_import(asn1_module, const char *);
void add_export(asn1_module, const char *);
int is_export(asn1_module, const char *);
int yyparse(void *scanner, asn1_module am);
int is_primitive_type(const Type *);
int is_tagged_type(const Type *);

int preserve_type(asn1_module am, const char *);
int seq_type(asn1_module am, const char *);

struct decoration {
    char *field_type;           /* C type name */
    char *field_name;           /* C struct field name */
    char *copy_function_name;   /* copy constructor function name */
    char *free_function_name;   /* destructor function name */
    char *header_name;          /* header name */
    unsigned int decorated:1;
    unsigned int first:1;       /* optional */
    unsigned int opt:1;         /* optional */
    unsigned int ext:1;         /* external */
    unsigned int ptr:1;         /* external, pointer */
    unsigned int void_star:1;   /* external, void * */
    unsigned int struct_star:1; /* external, struct foo * */
};
int decorate_type(const char *, struct decoration *, ssize_t *);

void c_generate_header_of_codefile(asn1_module, const char *);
void close_codefile(asn1_module);

void get_open_type_defn_fields(const Type *, Member **, Member **, Field **,
                               Field **, int *);
void sort_object_set(IOSObjectSet *, Field *, IOSObject ***, size_t *);
int object_cmp(const void *, const void *);

int is_template_compat (const Symbol *);
void c_generate_template(asn1_module am, const Symbol *);
void c_generate_template_type_forward(asn1_module am, const char *);
void c_generate_template_objectset_forwards(asn1_module, const Symbol *);
void c_gen_template_import(asn1_module am, const Symbol *);

struct objid **objid2list(struct objid *);

extern const char *fuzzer_string;
extern int template_flag;
extern int original_order;
extern char *type_file_string;

extern int error_flag;

#endif /* __GEN_LOCL_H__ */
