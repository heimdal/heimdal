/***********************************************************************
 * Copyright (c) 2010, Secure Endpoints Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **********************************************************************/

#include "krb5_locl.h"

#ifndef _WIN32
#error  config_reg.c is only for Windows
#endif

#define REGPATH "SOFTWARE\\Heimdal"

/**
 * Parse a registry value as a configuration value
 *
 * The following registry value types are handled:
 *
 * - REG_DWORD: The decimal string representation is used as the
 *   value.
 *
 * - REG_SZ: The string is used as-is.
 *
 * - REG_EXPAND_SZ: Environment variables in the string are expanded
 *   and the result is used as the value.
 *
 * - REG_MULTI_SZ: The list of strings is concatenated using a ' ' as
 *   a separator.  No quoting is performed.
 *
 * Any other value type is rejected.
 */
static krb5_error_code
parse_reg_value(krb5_context context,
                HKEY key, const char * valuename,
                DWORD type, DWORD cbdata, krb5_config_section ** parent)
{
    LONG                rcode;
    DWORD               cb;
    krb5_config_section *value;
    krb5_error_code     code = 0;

    BYTE                static_buffer[16384];
    BYTE                *pbuffer;

    /* Size adjustments */

    switch (type) {
    case REG_DWORD:
        if (cbdata != sizeof(DWORD)) {
            krb5_set_error_message(context, KRB5_CONFIG_BADFORMAT,
                                   "Unexpected size while reading registry value %s",
                                   valuename);
            return KRB5_CONFIG_BADFORMAT;
        }
        break;

    case REG_SZ:
    case REG_EXPAND_SZ:
        cbdata += sizeof(char); /* Accout for potential missing NUL
                                 * terminator. */
        break;

    case REG_MULTI_SZ:
        cbdata += sizeof(char) * 2;
        break;

    default:
        krb5_set_error_message(context, KRB5_CONFIG_BADFORMAT,
                               "Unexpected type while reading registry value %s",
                               valuename);
        return KRB5_CONFIG_BADFORMAT;
    }

    if (cbdata <= sizeof(static_buffer))
        pbuffer = &static_buffer[0];
    else {
        pbuffer = malloc(cbdata);
        if (pbuffer == NULL)
            return ENOMEM;
    }

    cb = cbdata;

    rcode = RegQueryValueExA(key, valuename, NULL, NULL, pbuffer, &cb);
    if (rcode != ERROR_SUCCESS) {
        krb5_set_error_message(context, KRB5_CONFIG_BADFORMAT,
                               "Unexpected error while reading registry value %s",
                               valuename);
        code = KRB5_CONFIG_BADFORMAT;
        goto done;
    }

    if (cb > cbdata) {
        krb5_set_error_message(context, KRB5_CONFIG_BADFORMAT,
                               "Unexpected error while reading registry value %s",
                               valuename);
        code = KRB5_CONFIG_BADFORMAT;
        goto done;
    }

    value = get_entry(parent, valuename, krb5_config_string);
    if (value == NULL) {
        code = ENOMEM;
        goto done;
    }

    if (value->u.string != NULL) {
        free(value->u.string);
        value->u.string = NULL;
    }

    switch (type) {
    case REG_DWORD:
    {
        asprintf(&value->u.string, "%d", *((DWORD *) pbuffer));
    }
    break;

    case REG_SZ:
    {
        char * str = (char *) pbuffer;

        if (str[cb - 1] != '\0')
            str[cb] = '\0';

        value->u.string = strdup(str);
    }
    break;

    case REG_EXPAND_SZ:
    {
        char    *str = (char *) pbuffer;
        char    expsz[32768];   /* Size of output buffer for
                                 * ExpandEnvironmentStrings() is
                                 * limited to 32K. */

        if (str[cb - 1] != '\0')
            str[cb] = '\0';

        if (ExpandEnvironmentStrings(str, expsz, sizeof(expsz)/sizeof(expsz[0])) != 0) {
            value->u.string = strdup(expsz);
        } else {
            code = KRB5_CONFIG_BADFORMAT;
            krb5_set_error_message(context, KRB5_CONFIG_BADFORMAT,
                                   "Overflow while expanding environment strings for registry value %s", valuename);
        }
    }
    break;

    case REG_MULTI_SZ:
    {
        char * str = (char *) pbuffer;
        char * iter;

        str[cbdata - 1] = '\0';
        str[cbdata - 2] = '\0';

        for (iter = str; *iter;) {
            size_t len = strlen(iter);

            iter += len;
            if (iter[1] != '\0')
                *iter++ = ' ';
            else
                break;
        }

        value->u.string = strdup(str);
    }
    break;
    }

done:
    if (pbuffer != static_buffer && pbuffer != NULL)
        free(pbuffer);

    return code;
}

static krb5_error_code
parse_reg_values(krb5_context context,
                 HKEY key,
                 krb5_config_section ** parent)
{
    DWORD index;
    LONG  rcode;

    for (index = 0; ; index ++) {
        char    name[16385];
        DWORD   cch = sizeof(name)/sizeof(name[0]);
        DWORD   type;
        DWORD   cbdata = 0;
        krb5_error_code code;

        rcode = RegEnumValue(key, index, name, &cch, NULL,
                             &type, NULL, &cbdata);
        if (rcode != ERROR_SUCCESS)
            break;

        if (cbdata == 0)
            continue;

        code = parse_reg_value(context, key, name, type, cbdata, parent);
        if (code != 0)
            return code;
    }

    return 0;
}

static krb5_error_code
parse_reg_subkeys(krb5_context context,
                  HKEY key,
                  krb5_config_section ** parent)
{
    DWORD index;
    LONG  rcode;

    for (index = 0; ; index ++) {
        HKEY    subkey = NULL;
        char    name[256];
        DWORD   cch = sizeof(name)/sizeof(name[0]);
        krb5_config_section     *section = NULL;
        krb5_error_code         code;

        rcode = RegEnumKeyEx(key, index, name, &cch, NULL, NULL, NULL, NULL);
        if (rcode != ERROR_SUCCESS)
            break;

        rcode = RegOpenKeyEx(key, name, 0, KEY_READ, &subkey);
        if (rcode != ERROR_SUCCESS)
            continue;

        section = get_entry(parent, name, krb5_config_list);
        if (section == NULL) {
            RegCloseKey(subkey);
            return ENOMEM;
        }

        code = parse_reg_values(context, subkey, &section->u.list);
        if (code) {
            RegCloseKey(subkey);
            return code;
        }

        code = parse_reg_subkeys(context, subkey, &section->u.list);
        if (code) {
            RegCloseKey(subkey);
            return code;
        }

        RegCloseKey(subkey);
    }

    return 0;
}

static krb5_error_code
parse_reg_root(krb5_context context,
               HKEY key,
               krb5_config_section ** parent)
{
    krb5_config_section *libdefaults = NULL;
    krb5_error_code     code = 0;

    libdefaults = get_entry(parent, "libdefaults", krb5_config_list);
    if (libdefaults == NULL) {
        krb5_set_error_message(context, ENOMEM, "Out of memory while parsing configuration");
        return ENOMEM;
    }

    code = parse_reg_values(context, key, &libdefaults->u.list);
    if (code)
        return code;

    return parse_reg_subkeys(context, key, parent);
}

/**
 * Load configuration from registry
 *
 * The registry keys 'HKCU\Software\Heimdal' and
 * 'HKLM\Software\Heimdal' are treated as krb5.conf files.  Each
 * registry key corresponds to a configuration section (or bound list)
 * and each value in a registry key is treated as a bound value.  The
 * set of values that are directly under the Heimdal key are treated
 * as if they were defined in the [libdefaults] section.
 *
 * @see parse_reg_value() for details about how each type of value is handled.
 */
krb5_error_code
krb5_load_config_from_registry(krb5_context context,
                               krb5_config_section ** res)
{
    HKEY        key = NULL;
    LONG        rcode;
    krb5_error_code code = 0;

    rcode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGPATH, 0, KEY_READ, &key);
    if (rcode == ERROR_SUCCESS) {
        code = parse_reg_root(context, key, res);
        RegCloseKey(key);
        key = NULL;

        if (code)
            return code;
    }

    rcode = RegOpenKeyEx(HKEY_CURRENT_USER, REGPATH, 0, KEY_READ, &key);
    if (rcode == ERROR_SUCCESS) {
        code = parse_reg_root(context, key, res);
        RegCloseKey(key);
        key = NULL;

        if (code)
            return code;
    }

    return 0;
}
