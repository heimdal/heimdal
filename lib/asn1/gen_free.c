/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
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

#include "gen_locl.h"

RCSID("$Id$");

/* Set by generate_type_free() for use by gen_open_type_free() */
static const char *current_free_basetype;

/*
 * Generate code to free decoded open type values in the _ioschoice union.
 */
static void
gen_open_type_free(const char *name, const Type *t)
{
    Member *opentypemember = NULL, *typeidmember = NULL;
    Field *opentypefield = NULL, *typeidfield = NULL;
    IOSObjectSet *os;
    IOSObject **objects = NULL;
    size_t nobjs, i;
    int is_array_of_open_type = 0;

    if (!t->actual_parameter)
        return;

    get_open_type_defn_fields(t, &typeidmember, &opentypemember,
                              &typeidfield, &opentypefield,
                              &is_array_of_open_type);
    if (!opentypemember || !typeidmember)
        return;

    os = t->actual_parameter;
    sort_object_set(os, typeidfield, &objects, &nobjs);
    if (nobjs == 0)
        return;

    fprintf(codefile, "/* Free open type for %s */\n", opentypemember->gen_name);
    fprintf(codefile, "switch ((%s)->_ioschoice_%s.element) {\n",
            name, opentypemember->gen_name);

    for (i = 0; i < nobjs; i++) {
        ObjectField *typeidobjf = NULL, *opentypeobjf = NULL;
        ObjectField *of;

        HEIM_TAILQ_FOREACH(of, objects[i]->objfields, objfields) {
            if (strcmp(of->name, typeidfield->name) == 0)
                typeidobjf = of;
            else if (strcmp(of->name, opentypefield->name) == 0)
                opentypeobjf = of;
        }
        if (!typeidobjf || !opentypeobjf)
            continue;

        fprintf(codefile, "case choice_%s_iosnum_%s:\n",
                current_free_basetype,
                typeidobjf->value->s->gen_name);

        if (!is_array_of_open_type) {
            fprintf(codefile,
                    "if ((%s)->_ioschoice_%s.u.%s) {\n"
                    "free_%s((%s)->_ioschoice_%s.u.%s);\n"
                    "free((%s)->_ioschoice_%s.u.%s);\n"
                    "(%s)->_ioschoice_%s.u.%s = NULL;\n"
                    "}\n",
                    name, opentypemember->gen_name,
                    objects[i]->symbol->gen_name,
                    opentypeobjf->type->symbol->gen_name,
                    name, opentypemember->gen_name,
                    objects[i]->symbol->gen_name,
                    name, opentypemember->gen_name,
                    objects[i]->symbol->gen_name,
                    name, opentypemember->gen_name,
                    objects[i]->symbol->gen_name);
        } else {
            fprintf(codefile,
                    "if ((%s)->_ioschoice_%s.val) {\n"
                    "unsigned int ot_i;\n"
                    "for (ot_i = 0; ot_i < (%s)->_ioschoice_%s.len; ot_i++)\n"
                    "free_%s(&(%s)->_ioschoice_%s.val[ot_i]);\n"
                    "free((%s)->_ioschoice_%s.val);\n"
                    "(%s)->_ioschoice_%s.val = NULL;\n"
                    "(%s)->_ioschoice_%s.len = 0;\n"
                    "}\n",
                    name, opentypemember->gen_name,
                    name, opentypemember->gen_name,
                    opentypeobjf->type->symbol->gen_name,
                    name, opentypemember->gen_name,
                    name, opentypemember->gen_name,
                    name, opentypemember->gen_name,
                    name, opentypemember->gen_name);
        }

        fprintf(codefile, "break;\n");
    }

    fprintf(codefile,
            "default: break;\n"
            "}\n"
            "(%s)->_ioschoice_%s.element = 0;\n",
            name, opentypemember->gen_name);

    free(objects);
}

static void
free_primitive (const char *typename, const char *name)
{
    fprintf (codefile, "der_free_%s(%s);\n", typename, name);
}

static void
free_type (const char *name, const Type *t, int preserve)
{
    switch (t->type) {
    case TType:
#if 0
	free_type (name, t->symbol->type, preserve);
#endif
	fprintf (codefile, "free_%s(%s);\n", t->symbol->gen_name, name);
	break;
    case TInteger:
	if (t->range == NULL && t->members == NULL) {
	    free_primitive ("heim_integer", name);
	    break;
	}
        HEIM_FALLTHROUGH;
    case TBoolean:
    case TEnumerated :
    case TNull:
    case TGeneralizedTime:
    case TUTCTime:
        /*
         * This doesn't do much, but it leaves zeros where garbage might
         * otherwise have been found.  Gets us closer to having the equivalent
         * of a memset()-to-zero data structure after calling the free
         * functions.
         */
        fprintf(codefile, "*%s = 0;\n", name);
	break;
    case TBitString:
	if (HEIM_TAILQ_EMPTY(t->members))
	    free_primitive("bit_string", name);
	break;
    case TOctetString:
	free_primitive ("octet_string", name);
	break;
    case TChoice:
    case TSet:
    case TSequence: {
	Member *m, *have_ellipsis = NULL;

	if (t->members == NULL)
	    break;

	if ((t->type == TSequence || t->type == TChoice) && preserve)
	    fprintf(codefile, "der_free_octet_string(&data->_save);\n");

	if(t->type == TChoice)
	    fprintf(codefile, "switch((%s)->element) {\n", name);

	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    char *s;

	    if (m->ellipsis){
		have_ellipsis = m;
		continue;
	    }

	    if(t->type == TChoice)
		fprintf(codefile, "case %s:\n", m->label);
	    if (asprintf (&s, "%s(%s)->%s%s",
			  m->optional ? "" : "&", name,
			  t->type == TChoice ? "u." : "", m->gen_name) < 0 || s == NULL)
		errx(1, "malloc");
	    if(m->optional)
		fprintf(codefile, "if(%s) {\n", s);
	    free_type (s, m->type, FALSE);
	    if(m->optional)
		fprintf(codefile,
			"free(%s);\n"
			"%s = NULL;\n"
			"}\n",s, s);
	    free (s);
	    if(t->type == TChoice)
		fprintf(codefile, "break;\n");
	}

	if(t->type == TChoice) {
	    if (have_ellipsis)
		fprintf(codefile,
			"case %s:\n"
			"der_free_octet_string(&(%s)->u.%s);\n"
			"break;",
			have_ellipsis->label,
			name, have_ellipsis->gen_name);
	    fprintf(codefile, "}\n");
        }
	if (t->type == TSequence || t->type == TSet)
	    gen_open_type_free(name, t);
	break;
    }
    case TSetOf:
    case TSequenceOf: {
	char *n;

	fprintf (codefile, "if ((%s)->val)\nwhile((%s)->len){\n", name, name);
	if (asprintf (&n, "&(%s)->val[(%s)->len-1]", name, name) < 0 || n == NULL)
	    errx(1, "malloc");
	free_type(n, t->subtype, FALSE);
	fprintf(codefile,
		"(%s)->len--;\n"
		"} else (%s)->len = 0;\n",
		name, name);
	fprintf(codefile,
		"free((%s)->val);\n"
		"(%s)->val = NULL;\n", name, name);
	free(n);
	break;
    }
    case TGeneralString:
	free_primitive ("general_string", name);
	break;
    case TTeletexString:
	free_primitive ("general_string", name);
	break;
    case TUTF8String:
	free_primitive ("utf8string", name);
	break;
    case TPrintableString:
	free_primitive ("printable_string", name);
	break;
    case TIA5String:
	free_primitive ("ia5_string", name);
	break;
    case TBMPString:
	free_primitive ("bmp_string", name);
	break;
    case TUniversalString:
	free_primitive ("universal_string", name);
	break;
    case TVisibleString:
	free_primitive ("visible_string", name);
	break;
    case TTag:
	free_type (name, t->subtype, preserve);
	break;
    case TOID :
	free_primitive ("oid", name);
	break;
    default :
	abort ();
    }
}

void
generate_type_free (const Symbol *s)
{
    struct decoration deco;
    ssize_t more_deco = -1;
    int preserve = preserve_type(s->name) ? TRUE : FALSE;

    current_free_basetype = s->gen_name;

    fprintf (codefile, "void ASN1CALL\n"
	     "free_%s(%s *data)\n"
	     "{\n",
	     s->gen_name, s->gen_name);

    free_type ("data", s->type, preserve);
    while (decorate_type(s->gen_name, &deco, &more_deco)) {
        if (deco.ext && deco.free_function_name == NULL) {
            /* Decorated with field of external type but no free function */
            if (deco.ptr)
                fprintf(codefile, "(data)->%s = 0;\n", deco.field_name);
            else
                fprintf(codefile,
                        "memset(&(data)->%s, 0, sizeof((data)->%s));\n",
                        deco.field_name, deco.field_name);
        } else if (deco.ext) {
            /* Decorated with field of external type w/ free function */
            if (deco.ptr) {
                fprintf(codefile, "if ((data)->%s) {\n", deco.field_name);
                fprintf(codefile, "%s((data)->%s);\n",
                        deco.free_function_name, deco.field_name);
                fprintf(codefile, "(data)->%s = 0;\n", deco.field_name);
                fprintf(codefile, "}\n");
            } else {
                fprintf(codefile, "%s(&(data)->%s);\n",
                        deco.free_function_name, deco.field_name);
                fprintf(codefile,
                        "memset(&(data)->%s, 0, sizeof((data)->%s));\n",
                        deco.field_name, deco.field_name);
            }
        } else if (deco.opt) {
            /* Decorated with optional field of ASN.1 type */
            fprintf(codefile, "if ((data)->%s) {\n", deco.field_name);
            fprintf(codefile, "free_%s((data)->%s);\n",
                    deco.field_type, deco.field_name);
            fprintf(codefile, "free((data)->%s);\n", deco.field_name);
            fprintf(codefile, "(data)->%s = NULL;\n", deco.field_name);
            fprintf(codefile, "}\n");
        } else {
            /* Decorated with required field of ASN.1 type */
            fprintf(codefile, "free_%s(&(data)->%s);\n",
                    deco.field_type, deco.field_name);
        }
        free(deco.field_type);
    }
    fprintf (codefile, "}\n\n");
}
