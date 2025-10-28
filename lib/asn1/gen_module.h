/*
 * Copyright (c) 2025 Jeffrey Kintscher.
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

#ifndef __GEN_MODULE_H__
#define __GEN_MODULE_H__

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include "getarg.h"
#include "hash.h"
#include "heimqueue.h"


#define STEM "asn1"

/*
 * XXX We need to move all module state out of globals and into a struct that
 * we pass around when parsing and compiling a module, and also that we keep on
 * a linked list of parsed modules.
 *
 * This is needed to:
 *
 *  - implement IMPORTS correctly, because we need to know the type of a symbol
 *    in order to emit an extern declaration of it
 *  - implement value parsing
 *  - implement an ASN.1 library that does value parsing
 *
 * Value parsing, in particular, would be fantastic.  We could then have
 * options in hxtool(1) to load arbitrary ASN.1 modules and then parse SAN
 * values given in ASN.1 value syntax on the command-line or in files.  Eat
 * your heart out OpenSSL if we do this!
 *
 * As well we'll need a `-I' option to the compiler so it knows where to find
 * modules to IMPORT FROM.
 */

struct symbol;
struct type;
struct value;

struct template {
    char *line;
    char *tt;
    char *offset;
    char *ptr;
    HEIM_TAILQ_ENTRY(template) members;
};

HEIM_TAILQ_HEAD(templatehead, template);

struct tlist {
    char *name;
    char *header;
    struct templatehead template;
    HEIM_TAILQ_ENTRY(tlist) tmembers;
};

HEIM_TAILQ_HEAD(tlisthead, tlist);

typedef struct asn1_module {
    /* Name of ASN.1 module file: */
    const char *orig_filename;
    /* Name of file to always include for common type definitions: */
    const char *type_file_string;
    /* Name of public header file for module: */
    const char *header;
    /* Name of private header file for module: */
    const char *privheader;
    /* Basename of module: */
    const char *headerbase;
    /* Name of template file for module: */
    const char *template_filename;
    /* Fuzzer string: */
    const char *fuzzer_string;
    /* Open stdio file handles for output: */
    FILE *jsonfile;
    FILE *privheaderfile;
    FILE *headerfile;
    FILE *oidsfile;
    FILE *codefile;
    FILE *logfile;
    FILE *templatefile;
    FILE *symsfile;
    /* Module contents: */
    struct sexport *exports;
    struct import *imports;
    Hashtab *htab;  /* symbols */
    /* Template state: */
    // struct templatehead *template;  // TODO unneeded?
    struct tlisthead *tlistmaster;
    unsigned long numdups;
    /* Copy state: */
    int used_fail;
    /* CLI options and flags needed everywhere: */
    getarg_strings decorate;
    getarg_strings preserve;
    getarg_strings seq;
    const char *enum_prefix;
    unsigned int one_code_file:1;
    unsigned int support_ber:1;
    unsigned int parse_units_flag:1;
    unsigned int prefix_enum:1; /* Should be a getarg_strings of bitrsting types to do this for */
    unsigned int rfc1510_bitstring:1; /* Should be a getarg_strings of bitrsting types to do this for */
    unsigned int template_flag:1;
    unsigned int original_order:1;
    unsigned int error_flag:1;
} *asn1_module;

asn1_module new_asn1_module(getarg_strings, getarg_strings, getarg_strings, const char *,
                            unsigned int, unsigned int, unsigned int, unsigned int,
                            unsigned int, const char *, unsigned int, unsigned int,
                            const char *);

#endif  // __GEN_MODULE_H__
