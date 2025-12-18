/*
 * Copyright (c) 2025 Jeffrey Kintscher
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

#include <stdlib.h>
#include "gen_module.h"

asn1_module new_asn1_module(getarg_strings decorate,
                            getarg_strings preserve,
                            getarg_strings seq,
                            const char *enum_prefix,
                            unsigned int one_code_file,
                            unsigned int support_ber,
                            unsigned int parse_units_flag,
                            unsigned int prefix_enum,
                            unsigned int rfc1510_bitstring,
                            const char *fuzzer_string,
                            unsigned int template_flag,
                            unsigned int original_order,
                            const char *type_file_string)
{
    asn1_module am = calloc(sizeof(struct asn1_module), 1);
    if (am == NULL)
        errx(1, "calloc");

    am->decorate = decorate;
    am->enum_prefix = enum_prefix;
    am->fuzzer_string = fuzzer_string;
    am->headerbase = STEM;
    am->one_code_file = one_code_file;
    am->original_order = original_order;
    am->parse_units_flag = parse_units_flag;
    am->preserve = preserve;
    am->prefix_enum = prefix_enum;
    am->rfc1510_bitstring = rfc1510_bitstring;
    am->seq = seq;
    am->support_ber = support_ber;
    am->template_flag = template_flag;
    am->tlistmaster = calloc(sizeof(struct tlisthead), 1);
    if (am == NULL)
        errx(1, "calloc");
    am->tlistmaster->tqh_last = &am->tlistmaster->tqh_first;
    am->type_file_string = type_file_string;

    return am;
}
