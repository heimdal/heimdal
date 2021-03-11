/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

extern const char *enum_prefix;
extern int prefix_enum;

RCSID("$Id$");

FILE *privheaderfile, *headerfile, *oidsfile, *codefile, *logfile, *templatefile;
FILE *symsfile;

#define STEM "asn1"

static const char *orig_filename;
static char *privheader, *header, *template;
static const char *headerbase = STEM;

/* XXX same as der_length_tag */
static size_t
length_tag(unsigned int tag)
{
    size_t len = 0;

    if(tag <= 30)
        return 1;
    while(tag) {
        tag /= 128;
        len++;
    }
    return len + 1;
}

/*
 * list of all IMPORTs
 */

struct import {
    const char *module;
    struct import *next;
};

static struct import *imports = NULL;

void
add_import (const char *module)
{
    struct import *tmp = emalloc (sizeof(*tmp));

    tmp->module = module;
    tmp->next   = imports;
    imports     = tmp;

    fprintf (headerfile, "#include <%s_asn1.h>\n", module);
}

/*
 * List of all exported symbols
 */

struct sexport {
    const char *name;
    int defined;
    struct sexport *next;
};

static struct sexport *exports = NULL;

void
add_export (const char *name)
{
    struct sexport *tmp = emalloc (sizeof(*tmp));

    tmp->name   = name;
    tmp->next   = exports;
    exports     = tmp;
}

int
is_export(const char *name)
{
    struct sexport *tmp;

    if (exports == NULL) /* no export list, all exported */
	return 1;

    for (tmp = exports; tmp != NULL; tmp = tmp->next) {
	if (strcmp(tmp->name, name) == 0) {
	    tmp->defined = 1;
	    return 1;
	}
    }
    return 0;
}

const char *
get_filename (void)
{
    return orig_filename;
}

void
init_generate (const char *filename, const char *base)
{
    char *fn = NULL;

    orig_filename = filename;
    if (base != NULL) {
	headerbase = strdup(base);
	if (headerbase == NULL)
	    errx(1, "strdup");
    }

    /* public header file */
    if (asprintf(&header, "%s.h", headerbase) < 0 || header == NULL)
	errx(1, "malloc");
    if (asprintf(&fn, "%s.hx", headerbase) < 0 || fn == NULL)
	errx(1, "malloc");
    headerfile = fopen (fn, "w");
    if (headerfile == NULL)
	err (1, "open %s", fn);
    free(fn);
    fn = NULL;

    /* private header file */
    if (asprintf(&privheader, "%s-priv.h", headerbase) < 0 || privheader == NULL)
	errx(1, "malloc");
    if (asprintf(&fn, "%s-priv.hx", headerbase) < 0 || fn == NULL)
	errx(1, "malloc");
    privheaderfile = fopen (fn, "w");
    if (privheaderfile == NULL)
	err (1, "open %s", fn);
    free(fn);
    fn = NULL;

    /* template file */
    if (asprintf(&template, "%s-template.x", headerbase) < 0 || template == NULL)
	errx(1, "malloc");
    fprintf (headerfile,
	     "/* Generated from %s */\n"
	     "/* Do not edit */\n\n",
	     filename);
    fprintf (headerfile,
	     "#ifndef __%s_h__\n"
	     "#define __%s_h__\n\n", headerbase, headerbase);
    fprintf (headerfile,
	     "#include <stddef.h>\n"
	     "#include <stdint.h>\n"
	     "#include <time.h>\n\n");
    fprintf (headerfile,
	     "#ifndef __asn1_common_definitions__\n"
	     "#define __asn1_common_definitions__\n\n");
	fprintf (headerfile,
		 "#ifndef __HEIM_BASE_DATA__\n"
		 "#define __HEIM_BASE_DATA__ 1\n"
		 "struct heim_base_data {\n"
		 "    size_t length;\n"
		 "    void *data;\n"
		 "};\n"
		 "typedef struct heim_base_data heim_octet_string;\n"
		 "#endif\n\n");
    fprintf (headerfile,
	     "typedef struct heim_integer {\n"
	     "  size_t length;\n"
	     "  void *data;\n"
	     "  int negative;\n"
	     "} heim_integer;\n\n");
    fprintf (headerfile,
	     "typedef char *heim_general_string;\n\n"
	     );
    fprintf (headerfile,
	     "typedef char *heim_utf8_string;\n\n"
	     );
    fprintf (headerfile,
	     "typedef struct heim_base_data heim_printable_string;\n\n"
	     );
    fprintf (headerfile,
	     "typedef struct heim_base_data heim_ia5_string;\n\n"
	     );
    fprintf (headerfile,
	     "typedef struct heim_bmp_string {\n"
	     "  size_t length;\n"
	     "  uint16_t *data;\n"
	     "} heim_bmp_string;\n\n");
    fprintf (headerfile,
	     "typedef struct heim_universal_string {\n"
	     "  size_t length;\n"
	     "  uint32_t *data;\n"
	     "} heim_universal_string;\n\n");
    fprintf (headerfile,
	     "typedef char *heim_visible_string;\n\n"
	     );
    fprintf (headerfile,
	     "typedef struct heim_oid {\n"
	     "  size_t length;\n"
	     "  unsigned *components;\n"
	     "} heim_oid;\n\n");
    fprintf (headerfile,
	     "typedef struct heim_bit_string {\n"
	     "  size_t length;\n"
	     "  void *data;\n"
	     "} heim_bit_string;\n\n");
    fprintf (headerfile,
	     "typedef struct heim_base_data heim_any;\n"
	     "typedef struct heim_base_data heim_any_set;\n"
	     "typedef struct heim_base_data HEIM_ANY;\n"
	     "typedef struct heim_base_data HEIM_ANY_SET;\n\n");

    fprintf (headerfile,
             "enum asn1_print_flags {\n"
             "   ASN1_PRINT_INDENT = 1,\n"
             "};\n\n");
    fputs("#define ASN1_MALLOC_ENCODE(T, B, BL, S, L, R)                  \\\n"
	  "  do {                                                         \\\n"
	  "    (BL) = length_##T((S));                                    \\\n"
	  "    (B) = malloc((BL));                                        \\\n"
	  "    if((B) == NULL) {                                          \\\n"
	  "      (R) = ENOMEM;                                            \\\n"
	  "    } else {                                                   \\\n"
	  "      (R) = encode_##T(((unsigned char*)(B)) + (BL) - 1, (BL), \\\n"
	  "                       (S), (L));                              \\\n"
	  "      if((R) != 0) {                                           \\\n"
	  "        free((B));                                             \\\n"
	  "        (B) = NULL;                                            \\\n"
	  "      }                                                        \\\n"
	  "    }                                                          \\\n"
	  "  } while (0)\n\n",
	  headerfile);
    fputs("#ifdef _WIN32\n"
	  "#ifndef ASN1_LIB\n"
	  "#define ASN1EXP  __declspec(dllimport)\n"
	  "#else\n"
	  "#define ASN1EXP\n"
	  "#endif\n"
	  "#define ASN1CALL __stdcall\n"
	  "#else\n"
	  "#define ASN1EXP\n"
	  "#define ASN1CALL\n"
	  "#endif\n",
	  headerfile);
    fprintf (headerfile, "struct units;\n\n");
    fprintf (headerfile, "#endif\n\n");
    if (asprintf(&fn, "%s_files", base) < 0 || fn == NULL)
	errx(1, "malloc");
    logfile = fopen(fn, "w");
    if (logfile == NULL)
	err (1, "open %s", fn);
    free(fn);
    fn = NULL;

    if (asprintf(&fn, "%s_oids.x", base) < 0 || fn == NULL)
	errx(1, "malloc");
    oidsfile = fopen(fn, "w");
    if (oidsfile == NULL)
	err (1, "open %s", fn);
    if (asprintf(&fn, "%s_syms.x", base) < 0 || fn == NULL)
	errx(1, "malloc");
    symsfile = fopen(fn, "w");
    if (symsfile == NULL)
	err (1, "open %s", fn);
    free(fn);
    fn = NULL;

    /* if one code file, write into the one codefile */
    if (one_code_file)
	return;

    templatefile = fopen (template, "w");
    if (templatefile == NULL)
	err (1, "open %s", template);

    fprintf (templatefile,
	     "/* Generated from %s */\n"
	     "/* Do not edit */\n\n"
	     "#include <stdio.h>\n"
	     "#include <stdlib.h>\n"
	     "#include <time.h>\n"
	     "#include <string.h>\n"
	     "#include <errno.h>\n"
	     "#include <limits.h>\n"
	     "#include <asn1_err.h>\n"
	     "#include <%s>\n",
	     filename,
	     type_file_string);

    fprintf (templatefile,
	     "#include <%s>\n"
	     "#include <%s>\n"
	     "#include <der.h>\n"
	     "#include <asn1-template.h>\n",
	     header, privheader);


}

void
close_generate (void)
{
    fprintf (headerfile, "#endif /* __%s_h__ */\n", headerbase);

    if (headerfile && fclose(headerfile) == EOF)
        err(1, "writes to public header file failed");
    if (privheaderfile && fclose(privheaderfile) == EOF)
        err(1, "writes to private header file failed");
    if (templatefile && fclose(templatefile) == EOF)
        err(1, "writes to template file failed");
    if (logfile) {
        fprintf(logfile, "\n");
        if (fclose(logfile) == EOF)
            err(1, "writes to log file failed");
    }
}

void
gen_assign_defval(const char *var, struct value *val)
{
    switch(val->type) {
    case stringvalue:
	fprintf(codefile, "if((%s = strdup(\"%s\")) == NULL)\nreturn ENOMEM;\n", var, val->u.stringvalue);
	break;
    case integervalue:
	fprintf(codefile, "%s = %lld;\n",
		var, (long long)val->u.integervalue);
	break;
    case booleanvalue:
	if(val->u.booleanvalue)
	    fprintf(codefile, "%s = 1;\n", var);
	else
	    fprintf(codefile, "%s = 0;\n", var);
	break;
    default:
	abort();
    }
}

void
gen_compare_defval(const char *var, struct value *val)
{
    switch(val->type) {
    case stringvalue:
	fprintf(codefile, "if(strcmp(%s, \"%s\") != 0)\n", var, val->u.stringvalue);
	break;
    case integervalue:
	fprintf(codefile, "if(%s != %lld)\n",
		var, (long long)val->u.integervalue);
	break;
    case booleanvalue:
	if(val->u.booleanvalue)
	    fprintf(codefile, "if(!%s)\n", var);
	else
	    fprintf(codefile, "if(%s)\n", var);
	break;
    default:
	abort();
    }
}

void
generate_header_of_codefile(const char *name)
{
    char *filename = NULL;

    if (codefile != NULL)
	abort();

    if (asprintf (&filename, "%s_%s.x", STEM, name) < 0 || filename == NULL)
	errx(1, "malloc");
    codefile = fopen (filename, "w");
    if (codefile == NULL)
	err (1, "fopen %s", filename);
    if (logfile)
        fprintf(logfile, "%s ", filename);
    free(filename);
    filename = NULL;
    fprintf (codefile,
	     "/* Generated from %s */\n"
	     "/* Do not edit */\n\n"
	     "#define  ASN1_LIB\n\n"
	     "#include <stdio.h>\n"
	     "#include <stdlib.h>\n"
	     "#include <time.h>\n"
	     "#include <string.h>\n"
	     "#include <errno.h>\n"
	     "#include <limits.h>\n"
	     "#include <%s>\n",
	     orig_filename,
	     type_file_string);

    fprintf (codefile,
	     "#include \"%s\"\n"
	     "#include \"%s\"\n",
	     header, privheader);
    fprintf (codefile,
	     "#include <asn1_err.h>\n"
	     "#include <der.h>\n"
	     "#include <asn1-template.h>\n\n");

    if (parse_units_flag)
	fprintf (codefile,
		 "#include <parse_units.h>\n\n");

#ifdef _WIN32
    fprintf(codefile, "#pragma warning(disable: 4101)\n\n");
#endif
}

void
close_codefile(void)
{
    if (codefile == NULL)
	abort();

    if (fclose(codefile) == EOF)
        err(1, "writes to source code file failed");
    codefile = NULL;
}


void
generate_constant (const Symbol *s)
{
    switch(s->value->type) {
    case booleanvalue:
	break;
    case integervalue:
        /*
         * Work around the fact that OpenSSL defines macros for PKIX constants
         * that we want to generate as enums, which causes conflicts for things
         * like ub-name (ub_name).
         */
        fprintf(headerfile,
                "#ifdef %s\n"
                "#undef %s\n"
                "#endif\n"
                "enum { %s = %lld };\n\n",
                s->gen_name, s->gen_name, s->gen_name,
                (long long)s->value->u.integervalue);
        if (is_export(s->name))
            fprintf(symsfile, "ASN1_SYM_INTVAL(\"%s\", \"%s\", %s, %lld)\n",
                    s->name, s->gen_name, s->gen_name,
                    (long long)s->value->u.integervalue);
	break;
    case nullvalue:
	break;
    case stringvalue:
	break;
    case objectidentifiervalue: {
	struct objid *o, **list;
	size_t i, len;
	char *gen_upper;

	if (!one_code_file)
	    generate_header_of_codefile(s->gen_name);

	len = 0;
	for (o = s->value->u.objectidentifiervalue; o != NULL; o = o->next)
	    len++;
	if (len == 0) {
	    printf("s->gen_name: %s",s->gen_name);
	    fflush(stdout);
	    break;
	}
	list = emalloc(sizeof(*list) * len);

	i = 0;
	for (o = s->value->u.objectidentifiervalue; o != NULL; o = o->next)
	    list[i++] = o;

	fprintf (headerfile, "/* OBJECT IDENTIFIER %s ::= { ", s->name);
	for (i = len ; i > 0; i--) {
	    o = list[i - 1];
	    fprintf(headerfile, "%s(%d) ",
		    o->label ? o->label : "label-less", o->value);
	}

	fprintf (codefile, "static unsigned oid_%s_variable_num[%lu] =  {",
		 s->gen_name, (unsigned long)len);
	for (i = len ; i > 0; i--) {
	    fprintf(codefile, "%d%s ", list[i - 1]->value, i > 1 ? "," : "");
	}
	fprintf(codefile, "};\n");

	fprintf (codefile, "const heim_oid asn1_oid_%s = "
		 "{ %lu, oid_%s_variable_num };\n\n",
		 s->gen_name, (unsigned long)len, s->gen_name);

        fprintf(oidsfile, "DEFINE_OID_WITH_NAME(%s)\n", s->gen_name);
        if (is_export(s->name))
            fprintf(symsfile, "ASN1_SYM_OID(\"%s\", \"%s\", %s)\n",
                    s->name, s->gen_name, s->gen_name);

	free(list);

	/* header file */

	gen_upper = strdup(s->gen_name);
	len = strlen(gen_upper);
	for (i = 0; i < len; i++)
	    gen_upper[i] = toupper((int)s->gen_name[i]);

	fprintf (headerfile, "} */\n");
	fprintf (headerfile,
		 "extern ASN1EXP const heim_oid asn1_oid_%s;\n"
		 "#define ASN1_OID_%s (&asn1_oid_%s)\n\n",
		 s->gen_name,
		 gen_upper,
		 s->gen_name);

	free(gen_upper);

	if (!one_code_file)
	    close_codefile();

	break;
    }
    default:
	abort();
    }
}

int
is_tagged_type(const Type *t)
{
    /*
     * Start by chasing aliasings like this:
     *
     * Type0 ::= ...
     * Type1 ::= Type0
     * ..
     * TypeN ::= TypeN-1
     *
     * to <Type0>, then check if <Type0> is tagged.
     */
    while (t->type == TType) {
        if (t->subtype)
            t = t->subtype;
        else if (t->symbol && t->symbol->type)
            t = t->symbol->type;
        else
            abort();

    }
    if (t->type == TTag && t->tag.tagenv == TE_EXPLICIT)
        return 1;
    if (t->type == TTag) {
        if (t->subtype)
            return is_tagged_type(t->subtype);
        if (t->symbol && t->symbol->type)
            return is_tagged_type(t->symbol->type);
        /* This is the tag */
        return 1;
    }
    return 0;
}

int
is_primitive_type(const Type *t)
{
    /*
     * Start by chasing aliasings like this:
     *
     * Type0 ::= ...
     * Type1 ::= Type0
     * ..
     * TypeN ::= TypeN-1
     *
     * to <Type0>, then check if <Type0> is primitive.
     */
    while (t->type == TType &&
           t->symbol &&
           t->symbol->type) {
        if (t->symbol->type->type == TType)
            t = t->symbol->type; /* Alias */
        else if (t->symbol->type->type == TTag &&
                 t->symbol->type->tag.tagenv == TE_IMPLICIT)
            /*
             * IMPLICIT-tagged alias, something like:
             *
             * Type0 ::= [0] IMPLICIT ...
             *
             * Just recurse.
             */
            return is_primitive_type(t->symbol->type);
        else
            break;

    }
    /* EXPLICIT non-UNIVERSAL tags are always constructed */
    if (t->type == TTag && t->tag.tagclass != ASN1_C_UNIV &&
        t->tag.tagenv == TE_EXPLICIT)
        return 0;
    if (t->symbol && t->symbol->type) {
        /* EXPLICIT non-UNIVERSAL tags are constructed */
        if (t->symbol->type->type == TTag &&
            t->symbol->type->tag.tagclass != ASN1_C_UNIV &&
            t->symbol->type->tag.tagenv == TE_EXPLICIT)
            return 0;
        /* EXPLICIT UNIVERSAL tags are constructed if they are SEQUENCE/SET */
        if (t->symbol->type->type == TTag &&
            t->symbol->type->tag.tagclass == ASN1_C_UNIV) {
            switch (t->symbol->type->tag.tagvalue) {
            case UT_Sequence: return 0;
            case UT_Set: return 0;
            default: return 1;
            }
        }
    }
    switch(t->type) {
    case TInteger:
    case TBoolean:
    case TOctetString:
    case TBitString:
    case TEnumerated:
    case TGeneralizedTime:
    case TGeneralString:
    case TTeletexString:
    case TOID:
    case TUTCTime:
    case TUTF8String:
    case TPrintableString:
    case TIA5String:
    case TBMPString:
    case TUniversalString:
    case TVisibleString:
    case TNull:
	return 1;
    case TTag:
        return is_primitive_type(t->subtype);
    default:
	return 0;
    }
}

static void
space(int level)
{
    while(level-- > 0)
	fprintf(headerfile, "  ");
}

static const char *
last_member_p(struct member *m)
{
    struct member *n = HEIM_TAILQ_NEXT(m, members);
    if (n == NULL)
	return "";
    if (n->ellipsis && HEIM_TAILQ_NEXT(n, members) == NULL)
	return "";
    return ",";
}

static struct member *
have_ellipsis(Type *t)
{
    struct member *m;
    HEIM_TAILQ_FOREACH(m, t->members, members) {
	if (m->ellipsis)
	    return m;
    }
    return NULL;
}

static void
define_asn1 (int level, Type *t)
{
    switch (t->type) {
    case TType:
        if (!t->symbol && t->typeref.iosclass) {
            fprintf(headerfile, "%s.&%s",
                    t->typeref.iosclass->symbol->name,
                    t->typeref.field->name);
        } else
            fprintf(headerfile, "%s", t->symbol->name);
	break;
    case TInteger:
	if(t->members == NULL) {
            fprintf (headerfile, "INTEGER");
	    if (t->range)
		fprintf (headerfile, " (%lld..%lld)",
			 (long long)t->range->min,
			 (long long)t->range->max);
        } else {
	    Member *m;
            fprintf (headerfile, "INTEGER {\n");
	    HEIM_TAILQ_FOREACH(m, t->members, members) {
                space (level + 1);
		fprintf(headerfile, "%s(%d)%s\n", m->gen_name, m->val,
			last_member_p(m));
            }
	    space(level);
            fprintf (headerfile, "}");
        }
	break;
    case TBoolean:
	fprintf (headerfile, "BOOLEAN");
	break;
    case TOctetString:
	fprintf (headerfile, "OCTET STRING");
	break;
    case TEnumerated:
    case TBitString: {
	Member *m;

	space(level);
	if(t->type == TBitString)
	    fprintf (headerfile, "BIT STRING {\n");
	else
	    fprintf (headerfile, "ENUMERATED {\n");
	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    space(level + 1);
	    fprintf (headerfile, "%s(%d)%s\n", m->name, m->val,
		     last_member_p(m));
	}
	space(level);
	fprintf (headerfile, "}");
	break;
    }
    case TChoice:
    case TSet:
    case TSequence: {
	Member *m;
	size_t max_width = 0;

	if(t->type == TChoice)
	    fprintf(headerfile, "CHOICE {\n");
	else if(t->type == TSet)
	    fprintf(headerfile, "SET {\n");
	else
	    fprintf(headerfile, "SEQUENCE {\n");
	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    if(strlen(m->name) > max_width)
		max_width = strlen(m->name);
	}
	max_width += 3;
	if(max_width < 16) max_width = 16;
	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    size_t width = max_width;
	    space(level + 1);
	    if (m->ellipsis) {
		fprintf (headerfile, "...");
	    } else {
		width -= fprintf(headerfile, "%s", m->name);
		fprintf(headerfile, "%*s", (int)width, "");
		define_asn1(level + 1, m->type);
		if(m->optional)
		    fprintf(headerfile, " OPTIONAL");
	    }
	    if(last_member_p(m))
		fprintf (headerfile, ",");
	    fprintf (headerfile, "\n");
	}
	space(level);
	fprintf (headerfile, "}");
	break;
    }
    case TSequenceOf:
	fprintf (headerfile, "SEQUENCE OF ");
	define_asn1 (0, t->subtype);
	break;
    case TSetOf:
	fprintf (headerfile, "SET OF ");
	define_asn1 (0, t->subtype);
	break;
    case TGeneralizedTime:
	fprintf (headerfile, "GeneralizedTime");
	break;
    case TGeneralString:
	fprintf (headerfile, "GeneralString");
	break;
    case TTeletexString:
	fprintf (headerfile, "TeletexString");
	break;
    case TTag: {
	const char *classnames[] = { "UNIVERSAL ", "APPLICATION ",
				     "" /* CONTEXT */, "PRIVATE " };
	if(t->tag.tagclass != ASN1_C_UNIV)
	    fprintf (headerfile, "[%s%d] ",
		     classnames[t->tag.tagclass],
		     t->tag.tagvalue);
	if(t->tag.tagenv == TE_IMPLICIT)
	    fprintf (headerfile, "IMPLICIT ");
	define_asn1 (level, t->subtype);
	break;
    }
    case TUTCTime:
	fprintf (headerfile, "UTCTime");
	break;
    case TUTF8String:
	space(level);
	fprintf (headerfile, "UTF8String");
	break;
    case TPrintableString:
	space(level);
	fprintf (headerfile, "PrintableString");
	break;
    case TIA5String:
	space(level);
	fprintf (headerfile, "IA5String");
	break;
    case TBMPString:
	space(level);
	fprintf (headerfile, "BMPString");
	break;
    case TUniversalString:
	space(level);
	fprintf (headerfile, "UniversalString");
	break;
    case TVisibleString:
	space(level);
	fprintf (headerfile, "VisibleString");
	break;
    case TOID :
	space(level);
	fprintf(headerfile, "OBJECT IDENTIFIER");
	break;
    case TNull:
	space(level);
	fprintf (headerfile, "NULL");
	break;
    default:
	abort ();
    }
}

static void
getnewbasename(char **newbasename, int typedefp, const char *basename, const char *name)
{
    if (typedefp)
	*newbasename = strdup(name);
    else {
	if (name[0] == '*')
	    name++;
	if (asprintf(newbasename, "%s_%s", basename, name) < 0)
	    errx(1, "malloc");
    }
    if (*newbasename == NULL)
	err(1, "malloc");
}

static void define_type(int, const char *, const char *, Type *, Type *, int, int);

/*
 * Get the SET/SEQUENCE member pair and CLASS field pair defining an open type.
 *
 * There are three cases:
 *
 *  - open types embedded in OCTET STRING, with the open type object class
 *    relation declared via a constraint
 *
 *  - open types not embedded in OCTET STRING, which are really more like ANY
 *    DEFINED BY types, so, HEIM_ANY
 *
 *  - open types in a nested structure member where the type ID field is in a
 *    member of the ancestor structure (this happens in PKIX's `AttributeSet',
 *    where the open type is essentially a SET OF HEIM_ANY).
 *
 * In a type like PKIX's SingleAttribute the type ID member would be the one
 * named "type" and the open type member would be the one named "value", and
 * the corresponding fields of the ATTRIBUTE class would be named "id" and
 * "Type".
 *
 * NOTE: We assume a single open type member pair in any SET/SEQUENCE.  In
 *       principle there could be more pairs and we could iterate them, or
 *       better yet, we could be given the name of an open type member and then
 *       just find its related type ID member and fields, then our caller would
 *       iterate the SET/SEQUENCE type's members looking for open type members
 *       and would call this function for each one found.
 */
void
get_open_type_defn_fields(const Type *t,
                          Member **typeidmember,
                          Member **opentypemember,
                          Field **typeidfield,
                          Field **opentypefield,
                          int *is_array_of)
{
    Member *m;
    Field *junk1, *junk2;
    char *idmembername = NULL;

    if (!typeidfield) typeidfield = &junk1;
    if (!opentypefield) opentypefield = &junk2;

    *typeidfield = *opentypefield = NULL;
    *typeidmember = *opentypemember = NULL;
    *is_array_of = 0;

    /* Look for the open type member */
    HEIM_TAILQ_FOREACH(m, t->members, members) {
        Type *subtype = m->type;
        Type *sOfType = NULL;

        while (subtype->type == TTag ||
               subtype->type == TSetOf ||
               subtype->type == TSequenceOf) {
            if (subtype->type == TTag && subtype->subtype) {
                if (subtype->subtype->type == TOctetString ||
                    subtype->subtype->type == TBitString)
                    break;
                subtype = subtype->subtype;
            } else if (subtype->type == TSetOf || subtype->type == TSequenceOf) {
                sOfType = subtype;
                if (sOfType->symbol)
                    break;
                if (subtype->subtype)
                    subtype = subtype->subtype;
            } else
                break;
        }
        /*
         * If we traversed through a non-inlined SET OF or SEQUENCE OF type,
         * then this cannot be an open type field.
         */
        if (sOfType && sOfType->symbol)
            continue;
        /*
         * The type of the field we're interested in has to have an information
         * object constraint.
         */
        if (!subtype->constraint)
            continue;
        if (subtype->type != TType && subtype->type != TTag)
            continue;
        /*
         * Check if it's an ANY-like member or like an OCTET STRING CONTAINING
         * member.  Those are the only two possibilities.
         */
        if ((subtype->type == TTag || subtype->type == TType) &&
            subtype->subtype &&
            subtype->constraint->ctype == CT_CONTENTS &&
            subtype->constraint->u.content.type &&
            subtype->constraint->u.content.type->type == TType &&
            !subtype->constraint->u.content.type->subtype &&
            subtype->constraint->u.content.type->constraint &&
            subtype->constraint->u.content.type->constraint->ctype == CT_TABLE_CONSTRAINT) {
            /* Type like OCTET STRING or BIT STRING CONTAINING open type */
            *opentypemember = m;
            *opentypefield = subtype->constraint->u.content.type->typeref.field;
            *is_array_of = sOfType != NULL;
            idmembername = subtype->constraint->u.content.type->constraint->u.content.crel.membername;
            break;
        } else if (subtype->symbol && strcmp(subtype->symbol->name, "HEIM_ANY") == 0) {
            /* Open type, but NOT embedded in OCTET STRING or BIT STRING */
            *opentypemember = m;
            *opentypefield = subtype->typeref.field;
            *is_array_of = sOfType != NULL;
            idmembername = subtype->constraint->u.content.crel.membername;
            break;
        }
    }
    /* Look for the type ID member identified in the previous loop */
    HEIM_TAILQ_FOREACH(m, t->members, members) {
        if (!m->type->subtype || strcmp(m->name, idmembername))
            continue;
        if (m->type->constraint &&
            m->type->constraint->ctype == CT_TABLE_CONSTRAINT)
            *typeidfield = m->type->typeref.field;
        else if (m->type->subtype->constraint &&
                 m->type->subtype->constraint->ctype == CT_TABLE_CONSTRAINT)
            *typeidfield = m->type->subtype->typeref.field;
        else
            continue;
        /* This is the type ID field (because there _is_ a subtype) */
        *typeidmember = m;
        break;
    }
}

/*
 * Generate CHOICE-like struct fields for open types declared via
 * X.681/682/683 syntax.
 *
 * We could support multiple open type members in a SET/SEQUENCE, but for now
 * we support only one.
 */
static void
define_open_type(int level, const char *newbasename, const char *name, const char *basename, Type *pt, Type *t)
{
    Member *opentypemember, *typeidmember;
    Field *opentypefield, *typeidfield;
    ObjectField *of;
    IOSObjectSet *os = pt->actual_parameter;
    IOSObject **objects;
    size_t nobjs, i;
    int is_array_of_open_type;

    get_open_type_defn_fields(pt, &typeidmember, &opentypemember,
                              &typeidfield, &opentypefield,
                              &is_array_of_open_type);
    if (!opentypemember || !typeidmember ||
        !opentypefield  || !typeidfield)
        errx(1, "Open type specification in %s is incomplete", name);

    sort_object_set(os, typeidfield, &objects, &nobjs);

    fprintf(headerfile, "struct {\n");

    /* Iterate objects in the object set, gen enum labels */
    fprintf(headerfile, "enum { choice_%s_iosnumunknown = 0,\n",
            newbasename);
    for (i = 0; i < nobjs; i++) {
        HEIM_TAILQ_FOREACH(of, objects[i]->objfields, objfields) {
            if (strcmp(of->name, typeidfield->name))
                continue;
            if (!of->value || !of->value->s)
                errx(1, "Unknown value in value field %s of object %s",
                     of->name, objects[i]->symbol->name);
            fprintf(headerfile, "choice_%s_iosnum_%s,\n",
                    newbasename, of->value->s->gen_name);
        }
    }
    fprintf(headerfile, "} element;\n");

    if (is_array_of_open_type)
        fprintf(headerfile, "unsigned int len;\n");

    /* Iterate objects in the object set, gen union arms */
    fprintf(headerfile, "union {\nvoid *_any;\n");
    for (i = 0; i < nobjs; i++) {
        HEIM_TAILQ_FOREACH(of, objects[i]->objfields, objfields) {
            char *n = NULL;

            if (strcmp(of->name, opentypefield->name))
                continue;
            if (!of->type || (!of->type->symbol && of->type->type != TTag) ||
                of->type->tag.tagclass != ASN1_C_UNIV) {
                warnx("Ignoring unknown or unset type field %s of object %s",
                      of->name, objects[i]->symbol->name);
                continue;
            }

            if (asprintf(&n, "*%s", objects[i]->symbol->gen_name) < 0 || n == NULL)
                err(1, "malloc");
            define_type(level + 2, n, newbasename, NULL, of->type, FALSE, FALSE);
            free(n);
        }
    }
    if (is_array_of_open_type) {
        fprintf(headerfile, "} *val;\n} _ioschoice_%s;\n", opentypemember->gen_name);
    } else {
        fprintf(headerfile, "} u;\n");
        fprintf(headerfile, "} _ioschoice_%s;\n", opentypemember->gen_name);
    }
    free(objects);
}

static void
define_type(int level, const char *name, const char *basename, Type *pt, Type *t, int typedefp, int preservep)
{
    const char *label_prefix = NULL;
    const char *label_prefix_sep = NULL;
    char *newbasename = NULL;

    switch (t->type) {
    case TType:
	space(level);
        if (!t->symbol && t->actual_parameter)
            define_open_type(level, newbasename, name, basename, t, t);
        else if (!t->symbol && pt->actual_parameter)
            define_open_type(level, newbasename, name, basename, pt, t);
        else
            fprintf(headerfile, "%s %s;\n", t->symbol->gen_name, name);
	break;
    case TInteger:
        if (t->symbol && t->symbol->emitted_definition)
            break;

	space(level);
	if(t->members) {
            Member *m;

            label_prefix = prefix_enum ? name : (enum_prefix ? enum_prefix : "");
            label_prefix_sep = prefix_enum ? "_" : "";
            fprintf (headerfile, "enum %s {\n", typedefp ? name : "");
	    HEIM_TAILQ_FOREACH(m, t->members, members) {
                space (level + 1);
                fprintf(headerfile, "%s%s%s = %d%s\n",
                        label_prefix, label_prefix_sep,
                        m->gen_name, m->val, last_member_p(m));
            }
            fprintf(headerfile, "} %s;\n", name);
	} else if (t->range == NULL) {
            fprintf(headerfile, "heim_integer %s;\n", name);
	} else if (t->range->min < 0 &&
                   (t->range->min < INT_MIN || t->range->max > INT_MAX)) {
            fprintf(headerfile, "int64_t %s;\n", name);
	} else if (t->range->min < 0) {
	    fprintf (headerfile, "int %s;\n", name);
	} else if (t->range->max > UINT_MAX) {
	    fprintf (headerfile, "uint64_t %s;\n", name);
	} else {
	    fprintf (headerfile, "unsigned int %s;\n", name);
	}
	break;
    case TBoolean:
	space(level);
	fprintf (headerfile, "int %s;\n", name);
	break;
    case TOctetString:
	space(level);
	fprintf (headerfile, "heim_octet_string %s;\n", name);
	break;
    case TBitString: {
	Member *m;
	Type i;
	struct range range = { 0, UINT_MAX };
        size_t max_memno = 0;
        size_t bitset_size;

        if (t->symbol && t->symbol->emitted_definition)
            break;
        memset(&i, 0, sizeof(i));

        /*
         * range.max implies the size of the base unsigned integer used for the
         * bitfield members.  If it's less than or equal to UINT_MAX, then that
         * will be unsigned int, otherwise it will be uint64_t.
         *
         * We could just use uint64_t, yes, but for now, and in case that any
         * projects were exposing the BIT STRING types' C representations in
         * ABIs prior to this compiler supporting BIT STRING with larger
         * members, we stick to this.
         */
        HEIM_TAILQ_FOREACH(m, t->members, members) {
            if (m->val > max_memno)
                max_memno = m->val;
        }
        if (max_memno > 63)
            range.max = INT64_MAX;
        else
            range.max = 1ULL << max_memno;

	i.type = TInteger;
	i.range = &range;
	i.members = NULL;
	i.constraint = NULL;

	space(level);
	if(HEIM_TAILQ_EMPTY(t->members))
	    fprintf (headerfile, "heim_bit_string %s;\n", name);
	else {
	    int pos = 0;
	    getnewbasename(&newbasename, typedefp || level == 0, basename, name);

	    fprintf (headerfile, "struct %s {\n", newbasename);
	    HEIM_TAILQ_FOREACH(m, t->members, members) {
		char *n = NULL;

		/*
                 * pad unused bits beween declared members (hopefully this
                 * forces the compiler to give us an obvious layout)
                 */
		while (pos < m->val) {
		    if (asprintf (&n, "_unused%d:1", pos) < 0 || n == NULL)
			err(1, "malloc");
		    define_type(level + 1, n, newbasename, NULL, &i, FALSE, FALSE);
		    free(n);
		    pos++;
		}

		n = NULL;
		if (asprintf (&n, "%s:1", m->gen_name) < 0 || n == NULL)
		    errx(1, "malloc");
		define_type(level + 1, n, newbasename, NULL, &i, FALSE, FALSE);
		free (n);
		n = NULL;
		pos++;
	    }
	    /* pad unused tail (ditto) */
            bitset_size = max_memno;
            if (max_memno > 31)
                bitset_size += 64 - (max_memno % 64);
            else
                bitset_size = 32;
	    while (pos < bitset_size) {
		char *n = NULL;
		if (asprintf (&n, "_unused%d:1", pos) < 0 || n == NULL)
		    errx(1, "malloc");
		define_type(level + 1, n, newbasename, NULL, &i, FALSE, FALSE);
		free(n);
		pos++;
	    }

	    space(level);
	    fprintf (headerfile, "} %s;\n\n", name);
	}
	break;
    }
    case TEnumerated: {
	Member *m;

        if (t->symbol && t->symbol->emitted_definition)
            break;

        label_prefix = prefix_enum ? name : (enum_prefix ? enum_prefix : "");
        label_prefix_sep = prefix_enum ? "_" : "";
	space(level);
	fprintf (headerfile, "enum %s {\n", typedefp ? name : "");
	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    space(level + 1);
	    if (m->ellipsis)
		fprintf (headerfile, "/* ... */\n");
	    else
		fprintf(headerfile, "%s%s%s = %d%s\n",
                        label_prefix, label_prefix_sep,
                        m->gen_name, m->val, last_member_p(m));
	}
	space(level);
	fprintf (headerfile, "} %s;\n\n", name);
	break;
    }
    case TSet:
    case TSequence: {
	Member *m;

	getnewbasename(&newbasename, typedefp || level == 0, basename, name);

	space(level);
	fprintf (headerfile, "struct %s {\n", newbasename);
	if (t->type == TSequence && preservep) {
	    space(level + 1);
	    fprintf(headerfile, "heim_octet_string _save;\n");
	}
	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    if (m->ellipsis) {
		;
	    } else if (m->optional) {
		char *n = NULL;

		if (asprintf(&n, "*%s", m->gen_name) < 0 || n == NULL)
		    errx(1, "malloc");
		define_type(level + 1, n, newbasename, t, m->type, FALSE, FALSE);
		free (n);
	    } else
		define_type(level + 1, m->gen_name, newbasename, t, m->type, FALSE, FALSE);
	}
        if (t->actual_parameter && t->actual_parameter->objects)
            define_open_type(level, newbasename, name, basename, t, t);
	space(level);
	fprintf (headerfile, "} %s;\n", name);
	break;
    }
    case TSetOf:
    case TSequenceOf: {
	Type i;
	struct range range = { 0, UINT_MAX };

	getnewbasename(&newbasename, typedefp || level == 0, basename, name);

        memset(&i, 0, sizeof(i));
	i.type = TInteger;
	i.range = &range;

	space(level);
	fprintf (headerfile, "struct %s {\n", newbasename);
	define_type(level + 1, "len", newbasename, t, &i, FALSE, FALSE);
	define_type(level + 1, "*val", newbasename, t, t->subtype, FALSE, FALSE);
	space(level);
	fprintf (headerfile, "} %s;\n", name);
	break;
    }
    case TGeneralizedTime:
	space(level);
	fprintf (headerfile, "time_t %s;\n", name);
	break;
    case TGeneralString:
	space(level);
	fprintf (headerfile, "heim_general_string %s;\n", name);
	break;
    case TTeletexString:
	space(level);
	fprintf (headerfile, "heim_general_string %s;\n", name);
	break;
    case TTag:
        define_type(level, name, basename, t, t->subtype, typedefp, preservep);
	break;
    case TChoice: {
	int first = 1;
	Member *m;

	getnewbasename(&newbasename, typedefp || level == 0, basename, name);

	space(level);
	fprintf (headerfile, "struct %s {\n", newbasename);
	if (preservep) {
	    space(level + 1);
	    fprintf(headerfile, "heim_octet_string _save;\n");
	}
	space(level + 1);
	fprintf (headerfile, "enum %s_enum {\n", newbasename);
	m = have_ellipsis(t);
	if (m) {
	    space(level + 2);
	    fprintf (headerfile, "%s = 0,\n", m->label);
	    first = 0;
	}
	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    space(level + 2);
	    if (m->ellipsis)
		fprintf (headerfile, "/* ... */\n");
	    else
		fprintf (headerfile, "%s%s%s\n", m->label,
			 first ? " = 1" : "",
			 last_member_p(m));
	    first = 0;
	}
	space(level + 1);
	fprintf (headerfile, "} element;\n");
	space(level + 1);
	fprintf (headerfile, "union {\n");
	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    if (m->ellipsis) {
		space(level + 2);
		fprintf(headerfile, "heim_octet_string asn1_ellipsis;\n");
	    } else if (m->optional) {
		char *n = NULL;

		if (asprintf (&n, "*%s", m->gen_name) < 0 || n == NULL)
		    errx(1, "malloc");
		define_type(level + 2, n, newbasename, t, m->type, FALSE, FALSE);
		free (n);
	    } else
		define_type(level + 2, m->gen_name, newbasename, t, m->type, FALSE, FALSE);
	}
	space(level + 1);
	fprintf (headerfile, "} u;\n");
	space(level);
	fprintf (headerfile, "} %s;\n", name);
	break;
    }
    case TUTCTime:
	space(level);
	fprintf (headerfile, "time_t %s;\n", name);
	break;
    case TUTF8String:
	space(level);
	fprintf (headerfile, "heim_utf8_string %s;\n", name);
	break;
    case TPrintableString:
	space(level);
	fprintf (headerfile, "heim_printable_string %s;\n", name);
	break;
    case TIA5String:
	space(level);
	fprintf (headerfile, "heim_ia5_string %s;\n", name);
	break;
    case TBMPString:
	space(level);
	fprintf (headerfile, "heim_bmp_string %s;\n", name);
	break;
    case TUniversalString:
	space(level);
	fprintf (headerfile, "heim_universal_string %s;\n", name);
	break;
    case TVisibleString:
	space(level);
	fprintf (headerfile, "heim_visible_string %s;\n", name);
	break;
    case TOID :
	space(level);
	fprintf (headerfile, "heim_oid %s;\n", name);
	break;
    case TNull:
	space(level);
	fprintf (headerfile, "int %s;\n", name);
	break;
    default:
	abort ();
    }
    free(newbasename);
}

static void
declare_type(const Symbol *s, Type *t, int typedefp)
{
    char *newbasename = NULL;

    if (typedefp)
        fprintf(headerfile, "typedef ");

    switch (t->type) {
    case TType:
        define_type(0, s->gen_name, s->gen_name, NULL, s->type, TRUE, TRUE);
        if (template_flag)
            generate_template_type_forward(s->gen_name);
        emitted_declaration(s);
        return;
    case TInteger:
    case TBoolean:
    case TOctetString:
    case TBitString: 
    case TEnumerated: 
    case TGeneralizedTime:
    case TGeneralString:
    case TTeletexString:
    case TUTCTime:
    case TUTF8String:
    case TPrintableString:
    case TIA5String:
    case TBMPString:
    case TUniversalString:
    case TVisibleString:
    case TOID :
    case TNull:
        define_type(0, s->gen_name, s->gen_name, NULL, s->type, TRUE, TRUE);
        if (template_flag)
            generate_template_type_forward(s->gen_name);
        emitted_declaration(s);
        emitted_definition(s);
        return;
    case TTag:
	declare_type(s, t->subtype, FALSE);
        emitted_declaration(s);
	return;
    default:
        break;
    }

    switch (t->type) {
    case TSet:
    case TSequence:
	getnewbasename(&newbasename, TRUE, s->gen_name, s->gen_name);
	fprintf(headerfile, "struct %s %s;\n", newbasename, s->gen_name);
	break;
    case TSetOf:
    case TSequenceOf:
	getnewbasename(&newbasename, TRUE, s->gen_name, s->gen_name);
	fprintf(headerfile, "struct %s %s;\n", newbasename, s->gen_name);
	break;
    case TChoice:
	getnewbasename(&newbasename, TRUE, s->gen_name, s->gen_name);
	fprintf(headerfile, "struct %s %s;\n", newbasename, s->gen_name);
	break;
    default:
	abort ();
    }
    free(newbasename);
    emitted_declaration(s);
}

static void generate_subtypes_header_helper(const Member *m);
static void generate_type_header(const Symbol *);

static void
generate_subtypes_header_helper(const Member *m)
{
    Member *sm;
    Symbol *s;

    if (m->ellipsis)
        return;
    if (m->type->symbol && (s = getsym(m->type->symbol->name)) &&
        !s->emitted_definition) {
        /* A field of some named type; recurse */
        if (!m->optional && !m->defval)
            generate_type_header(s);
        return;
    }
    if (!m->type->subtype && !m->type->members)
        return;
    if (m->type->type == TTag &&
        m->type->subtype && m->type->subtype->symbol &&
        (s = getsym(m->type->subtype->symbol->name))) {
        if (!m->optional && !m->defval)
            generate_type_header(s);
        return;
    }
    if (m->type->subtype) {
        switch (m->type->subtype->type) {
        case TSet:
        case TSequence:
        case TChoice:
            break;
        default:
            return;
        }
        /* A field of some anonymous (inlined) structured type */
        HEIM_TAILQ_FOREACH(sm, m->type->subtype->members, members) {
            generate_subtypes_header_helper(sm);
        }
    }
    if (m->type->members) {
        HEIM_TAILQ_FOREACH(sm, m->type->members, members) {
            generate_subtypes_header_helper(sm);
        }
    }
}

static void
generate_subtypes_header(const Symbol *s)
{
    Type *t = s->type;
    Member *m;

    /*
     * Recurse down structured types to make sure top-level types get
     * defined before they are referenced.
     *
     * We'll take care to skip OPTIONAL member fields of constructed types so
     * that we can have circular types like:
     *
     *  Foo ::= SEQUENCE {
     *    bar Bar OPTIONAL
     *  }
     *
     *  Bar ::= SEQUENCE {
     *    foo Foo OPTIONAL
     *  }
     *
     * not unlike XDR, which uses `*' to mean "optional", except in XDR it's
     * called a "pointer".  With some care we should be able to eventually
     * support the silly XDR linked list example:
     *
     *  ListOfFoo ::= SEQUENCE {
     *    someField SomeType,
     *    next ListOfFoo OPTIONAL
     *  }
     *
     * Not that anyone needs it -- just use a SEQUENCE OF and be done.
     */

    while (t->type == TTag && t->subtype) {
        switch (t->subtype->type) {
        case TTag:
        case TSet:
        case TSequence:
        case TChoice:
            t = t->subtype;
            continue;
        default:
            break;
        }
        break;
    }

    switch (t->type) {
    default: return;
    case TType: {
        Symbol *s2;
        if (t->symbol && (s2 = getsym(t->symbol->name)) != s)
            generate_type_header(s2);
        return;
    }
    case TSet:
    case TSequence:
    case TChoice:
        break;
    }

    HEIM_TAILQ_FOREACH(m, t->members, members) {
        generate_subtypes_header_helper(m);
    }
}

static void
generate_type_header (const Symbol *s)
{
    Type *t = s->type;
    if (!s->type)
        return;

    /*
     * Recurse down the types of member fields of `s' to make sure that
     * referenced types have had their definitions emitted already if the
     * member fields are not OPTIONAL/DEFAULTed.
     */
    generate_subtypes_header(s);
    fprintf(headerfile, "/*\n");
    fprintf(headerfile, "%s ::= ", s->name);
    define_asn1 (0, s->type);
    fprintf(headerfile, "\n*/\n\n");

    /*
     * Emit enums for the outermost tag of this type.  These are needed for
     * dealing with IMPLICIT tags so we know what to rewrite the tag to when
     * decoding.
     *
     * See gen_encode.c and gen_decode.c for a complete explanation.  Short
     * version: we need to change the prototypes of the length/encode/decode
     * functions to take an optional IMPLICIT tag to use instead of the type's
     * outermost tag, but for now we hack it, and to do that we need to know
     * the type's outermost tag outside the context of the bodies of the codec
     * functions we generate for it.  Using an enum means no extra space is
     * needed in stripped objects.
     */
    if (!s->emitted_tag_enums) {
        while (t->type == TType && s->type->symbol && s->type->symbol->type) {
            if (t->subtype)
                t = t->subtype;
            else
                t = s->type->symbol->type;
        }

        if (t->type == TType && t->symbol && strcmp(t->symbol->name, "HEIM_ANY")) {
            /*
             * This type is ultimately an alias of an imported type, so we don't
             * know its outermost tag here.
             */
            fprintf(headerfile,
                    "enum { asn1_tag_length_%s = asn1_tag_length_%s,\n"
                    "       asn1_tag_class_%s = asn1_tag_class_%s,\n"
                    "       asn1_tag_tag_%s = asn1_tag_tag_%s };\n",
                    s->gen_name, s->type->symbol->gen_name,
                    s->gen_name, s->type->symbol->gen_name,
                    s->gen_name, s->type->symbol->gen_name);
            emitted_tag_enums(s);
        } else if (t->type != TType) {
            /* This type's outermost tag is known here */
            fprintf(headerfile,
                    "enum { asn1_tag_length_%s = %lu,\n"
                    "       asn1_tag_class_%s = %d,\n"
                    "       asn1_tag_tag_%s = %d };\n",
                    s->gen_name, (unsigned long)length_tag(s->type->tag.tagvalue),
                    s->gen_name, s->type->tag.tagclass,
                    s->gen_name, s->type->tag.tagvalue);
            emitted_tag_enums(s);
        }
    }

    if (s->emitted_definition)
        return;

    if (is_export(s->name))
        fprintf(symsfile, "ASN1_SYM_TYPE(\"%s\", \"%s\", %s)\n",
                s->name, s->gen_name, s->gen_name);
    fprintf(headerfile, "typedef ");
    define_type(0, s->gen_name, s->gen_name, NULL, s->type, TRUE,
                preserve_type(s->name) ? TRUE : FALSE);
    fprintf(headerfile, "\n");

    emitted_definition(s);
}

void
generate_type_header_forwards(const Symbol *s)
{
    declare_type(s, s->type, TRUE);
    fprintf(headerfile, "\n");
    if (template_flag)
        generate_template_type_forward(s->gen_name);
}

void
generate_type (const Symbol *s)
{
    FILE *h;
    const char * exp;

    if (!one_code_file)
	generate_header_of_codefile(s->gen_name);

    generate_type_header(s);

    if (template_flag)
	generate_template(s);

    if (template_flag == 0 || is_template_compat(s) == 0) {
	generate_type_encode (s);
	generate_type_decode (s);
	generate_type_free (s);
	generate_type_length (s);
	generate_type_copy (s);
    }
    generate_type_seq (s);
    generate_glue (s->type, s->gen_name);

    /* generate prototypes */

    if (is_export(s->name)) {
	h = headerfile;
	exp = "ASN1EXP ";
    } else {
	h = privheaderfile;
	exp = "";
    }

    fprintf (h,
	     "%sint    ASN1CALL "
	     "decode_%s(const unsigned char *, size_t, %s *, size_t *);\n",
	     exp,
	     s->gen_name, s->gen_name);
    fprintf (h,
	     "%sint    ASN1CALL "
	     "encode_%s(unsigned char *, size_t, const %s *, size_t *);\n",
	     exp,
	     s->gen_name, s->gen_name);
    fprintf (h,
	     "%ssize_t ASN1CALL length_%s(const %s *);\n",
	     exp,
	     s->gen_name, s->gen_name);
    fprintf (h,
	     "%sint    ASN1CALL copy_%s  (const %s *, %s *);\n",
	     exp,
	     s->gen_name, s->gen_name, s->gen_name);
    fprintf (h,
	     "%svoid   ASN1CALL free_%s  (%s *);\n",
	     exp,
	     s->gen_name, s->gen_name);

    if (template_flag)
        fprintf(h,
                "%schar * ASN1CALL print_%s (const %s *, int);\n",
                exp,
                s->gen_name, s->gen_name);

    fprintf(h, "\n\n");

    if (!one_code_file) {
	fprintf(codefile, "\n\n");
	close_codefile();
    }
}
