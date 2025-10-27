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

static void
length_primitive (asn1_module am,
		  const char *typename,
		  const char *name,
		  const char *variable)
{
    fprintf (am->codefile, "%s += der_length_%s(%s);\n", variable, typename, name);
}

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


static int
length_type (asn1_module am, const char *name, const Type *t,
	     const char *variable, const char *tmpstr)
{
    switch (t->type) {
    case TType:
#if 0
	length_type (am, name, t->symbol->type);
#endif
	fprintf (am->codefile, "%s += length_%s(%s);\n",
		 variable, t->symbol->gen_name, name);
	break;
    case TInteger:
	if(t->members) {
	    fprintf(am->codefile,
		    "{\n"
		    "int enumint = *%s;\n", name);
	    length_primitive (am, "integer", "&enumint", variable);
	    fprintf(am->codefile, "}\n");
	} else if (t->range == NULL) {
	    length_primitive (am, "heim_integer", name, variable);
	} else if (t->range->min < 0 &&
                   (t->range->min < INT_MIN || t->range->max > INT_MAX)) {
	    length_primitive (am, "integer64", name, variable);
	} else if (t->range->min < 0) {
	    length_primitive (am, "integer", name, variable);
	} else if (t->range->max > UINT_MAX) {
	    length_primitive (am, "unsigned64", name, variable);
	} else {
	    length_primitive (am, "unsigned", name, variable);
	}
	break;
    case TBoolean:
	fprintf (am->codefile, "%s += 1;\n", variable);
	break;
    case TEnumerated :
	length_primitive (am, "enumerated", name, variable);
	break;
    case TOctetString:
	length_primitive (am, "octet_string", name, variable);
	break;
    case TBitString: {
	if (HEIM_TAILQ_EMPTY(t->members))
	    length_primitive(am, "bit_string", name, variable);
	else {
	    if (!am->rfc1510_bitstring) {
		Member *m;
		int pos = HEIM_TAILQ_LAST(t->members, memhead)->val;

		fprintf(am->codefile,
			"do {\n");
		HEIM_TAILQ_FOREACH_REVERSE(m, t->members, memhead, members) {
		    while (m->val / 8 < pos / 8) {
			pos -= 8;
		    }
		    fprintf (am->codefile,
			     "if((%s)->%s) { %s += %d; break; }\n",
			     name, m->gen_name, variable, (pos + 8) / 8);
		}
		fprintf(am->codefile,
			"} while(0);\n");
		fprintf (am->codefile, "%s += 1;\n", variable);
	    } else {
		fprintf (am->codefile, "%s += 5;\n", variable);
	    }
	}
	break;
    }
    case TSet:
    case TSequence:
    case TChoice: {
	Member *m, *have_ellipsis = NULL;

	if (t->members == NULL)
	    break;

	if(t->type == TChoice)
	    fprintf (am->codefile, "switch((%s)->element) {\n", name);

	HEIM_TAILQ_FOREACH(m, t->members, members) {
	    char *s;

	    if (m->ellipsis) {
		have_ellipsis = m;
		continue;
	    }

	    if(t->type == TChoice)
		fprintf(am->codefile, "case %s:\n", m->label);

	    if (asprintf (&s, "%s(%s)->%s%s",
			  m->optional ? "" : "&", name,
			  t->type == TChoice ? "u." : "", m->gen_name) < 0 || s == NULL)
		errx(1, "malloc");
	    if (m->optional)
		fprintf (am->codefile, "if(%s)", s);
	    else if(m->defval)
		GEN_COMPARE_DEFVAL(am, s + 1, m->defval);
	    fprintf (am->codefile, "{\n"
		     "size_t %s_oldret = %s;\n"
		     "%s = 0;\n", tmpstr, variable, variable);
	    length_type (am, s, m->type, "ret", m->gen_name);
	    fprintf (am->codefile, "ret += %s_oldret;\n", tmpstr);
	    fprintf (am->codefile, "}\n");
	    free (s);
	    if(t->type == TChoice)
		fprintf(am->codefile, "break;\n");
	}
	if(t->type == TChoice) {
	    if (have_ellipsis)
		fprintf(am->codefile,
			"case %s:\n"
			"ret += (%s)->u.%s.length;\n"
			"break;\n",
			have_ellipsis->label,
			name,
			have_ellipsis->gen_name);
	    fprintf (am->codefile, "}\n"); /* switch */
	}
	break;
    }
    case TSetOf:
    case TSequenceOf: {
	char *n = NULL;
	char *sname = NULL;

	fprintf (am->codefile,
		 "{\n"
		 "size_t %s_oldret = %s;\n"
		 "unsigned int n_%s;\n"
		 "%s = 0;\n",
		 tmpstr, variable, tmpstr, variable);

	fprintf (am->codefile, "for(n_%s = (%s)->len; n_%s > 0; --n_%s){\n",
		 tmpstr, name, tmpstr, tmpstr);
	fprintf (am->codefile, "size_t %s_for_oldret = %s;\n"
		 "%s = 0;\n", tmpstr, variable, variable);
	if (asprintf (&n, "&(%s)->val[n_%s - 1]", name, tmpstr) < 0  || n == NULL)
	    errx(1, "malloc");
	if (asprintf (&sname, "%s_S_Of", tmpstr) < 0 || sname == NULL)
	    errx(1, "malloc");
	length_type(am, n, t->subtype, variable, sname);
	fprintf (am->codefile, "%s += %s_for_oldret;\n",
		 variable, tmpstr);
	fprintf (am->codefile, "}\n");

	fprintf (am->codefile,
		 "%s += %s_oldret;\n"
		 "}\n", variable, tmpstr);
	free(n);
	free(sname);
	break;
    }
    case TGeneralizedTime:
	length_primitive (am, "generalized_time", name, variable);
	break;
    case TGeneralString:
	length_primitive (am, "general_string", name, variable);
	break;
    case TTeletexString:
	length_primitive (am, "general_string", name, variable);
	break;
    case TUTCTime:
	length_primitive (am, "utctime", name, variable);
	break;
    case TUTF8String:
	length_primitive (am, "utf8string", name, variable);
	break;
    case TPrintableString:
	length_primitive (am, "printable_string", name, variable);
	break;
    case TIA5String:
	length_primitive (am, "ia5_string", name, variable);
	break;
    case TBMPString:
	length_primitive (am, "bmp_string", name, variable);
	break;
    case TUniversalString:
	length_primitive (am, "universal_string", name, variable);
	break;
    case TVisibleString:
	length_primitive (am, "visible_string", name, variable);
	break;
    case TNull:
	fprintf (am->codefile, "/* NULL */\n");
	break;
    case TTag:{
    	char *tname = NULL;
        int replace_tag = 0;
        int prim = !(t->tag.tagclass != ASN1_C_UNIV &&
                     t->tag.tagenv == TE_EXPLICIT) &&
            is_primitive_type(t->subtype);

	if (asprintf(&tname, "%s_tag", tmpstr) < 0 || tname == NULL)
	    errx(1, "malloc");
	length_type (am, name, t->subtype, variable, tname);
        /* See the comments in encode_type() about IMPLICIT tags */
        if (t->tag.tagenv == TE_IMPLICIT && !prim &&
            t->subtype->type != TSequenceOf && t->subtype->type != TSetOf &&
            t->subtype->type != TChoice) {
            if (t->subtype->symbol &&
                (t->subtype->type == TSequence ||
                 t->subtype->type == TSet))
                replace_tag = 1;
            else if (t->subtype->symbol && strcmp(t->subtype->symbol->name, "heim_any"))
                replace_tag = 1;
        } else if (t->tag.tagenv == TE_IMPLICIT && prim && t->subtype->symbol)
            replace_tag = is_tagged_type(t->subtype->symbol->type);
        if (replace_tag)
            /*
             * We're replacing the tag of the underlying type.  If that type is
             * imported, then we don't know its tag, so we rely on the
             * asn1_tag_tag_<TypeName> enum value we generated for it, and we
             * use the asn1_tag_length_<TypeName> enum value to avoid having to
             * call der_length_tag() at run-time.
             */
            fprintf(am->codefile, "ret += %lu - asn1_tag_length_%s;\n",
                    (unsigned long)length_tag(t->tag.tagvalue),
                    t->subtype->symbol->gen_name);
        else
            fprintf(am->codefile, "ret += %lu + der_length_len (ret);\n",
                    (unsigned long)length_tag(t->tag.tagvalue));
	free(tname);
	break;
    }
    case TOID:
	length_primitive (am, "oid", name, variable);
	break;
    default :
	abort ();
    }
    return 0;
}

void
c_generate_type_length (asn1_module am, const Symbol *s)
{
    fprintf (am->codefile,
	     "size_t ASN1CALL\n"
	     "length_%s(const %s *data)\n"
	     "{\n"
	     "size_t ret = 0;\n",
	     s->gen_name, s->gen_name);

    length_type (am, "data", s->type, "ret", "Top");
    fprintf (am->codefile, "return ret;\n}\n\n");
}

