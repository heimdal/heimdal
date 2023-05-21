/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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

#include "iprop.h"
#include "krb5-protos.h"
#include "krb5.h"
#include "private.h"
#include "../roken/vis-extras.h"
#include <stdint.h>

/*
 * This is the Heimdal Kerberos iprop-slave daemon, part of the Heimdal
 * multi-master iprop system.  Every KDC can be a master and a slave.  This
 * terminology is beginning to be obnoxious for non-cultural reasons.
 *
 * Theory of operation:
 *
 *  - every KDC maintains a local HDB and an iprop log for local operations
 *  - the iprop log implements a write-ahead log, roll-forward, two-phase
 *    commit system
 *  - the iprop log mechanism is orthogonal to the HDB implementation
 *  - all writes to the HDB must happen via lib/kadm5 -- where this is not
 *    possible to guarantee (e.g., LDAP), iprop is inappropriate for use
 *  - for single-master deployments, all KDCs except the master follow the
 *    master and disallow local HDB write access
 *  - for multi-master deployments, more than one KDC runs ipropd-master, and
 *    they must also arrange to run ipropd-slave in such a way that there is an
 *    iprop topology that allows HDB writes to flow from each master to every
 *    other master
 *  - for each transaction, the number of messages that will flow among all the
 *    masters will be 1 for each instance of ipropd-slave -- i.e., 1 for each
 *    iprop 'link', and we can refer to this as a magnification factor
 *
 *    For example, for a uni-directional circular topology, this write
 *    magnification will be equal to the number links, which will be equal to
 *    the number of master KDCs.  Double that if the circle is bi-directional.
 *
 *    For a linear topology where no KDC follows more than two others, and
 *    where every 'link' is bi-directional, the magnification factor will be
 *    2(N -1).
 *
 *    For a star topology with one primary master, the magnification factor
 *    will be 2(N -1).
 *
 *    For a full mesh topology the magnification factor will be N^2 - N.
 *
 *    A star topology within each site, plus a full mesh between sites for
 *    small numbers of sites, seems like a good idea.
 *
 * Multi-master iprop infinite loop avoidance:
 *
 *  - every HDB entry will have an extension listing:
 *     - the name of the KDC that wrote it
 *     - the names of all the KDCs that have seen this write
 *
 *  - every local HDB write outside of iprop will a) change the last-modify
 *    time of the entry, b) write the local KDC name as the last-modify-kdc,
 *    c) reset the list of names of KDCs that have seen this entry
 *
 *  - ipropd-slave will check that if the name of the local KDC is present in
 *    that extension of each entry received from upstream -- if not, then it
 *    will
 *
 *     - add the local KDC's name to the set of KDCs that have seen it
 *     - write that entry to the local HDB
 *     - write that entry to the local iprop log
 *     - signal any local ipropd-master that there has been a local HDB write
 *
 *    else it will drop that iprop entry
 *
 *  - ipropd-slave will maintain a separate iprop log for the upstream it is
 *    following, and will, as usual, keep only an uber block in it to track
 *    what upstream iprop version it has caught up to
 *
 * Multi-master conflict resolution:
 *
 *  - upon receipt of an iprop log entry ipropd-slave will read the same entry
 *    from the local HDB
 *
 *  - if the local HDB entry does not exist then ipropd-slave will accept the
 *    iprop log entry and apply it locally
 *
 *  - if the local HDB entry does exit then then ipropd-slave will apply the
 *    infinite loop avoidance algorithm described above
 *
 *  - if ipropd-slave chooses to apply the entry, first it will check which of
 *    the local or upstream entries has the large `kvno`, and will accept the
 *    one with the largest `kvno`
 *
 *  - if both entries have the same `kvno`, then ipropd-slave will accept the
 *    entry that has the largest last-modify time
 *
 * Split-brain events:
 *
 *  - a split-brain event happens whenever an ipropd-slave instance cannot
 *    connect to its upstream for some time, or whenever an ipropd-slave
 *    instance is stopped for some time
 *
 *  - upon resuming normal operation, ipropd-slave can either find that it can
 *    perform incremental propagation from the upstream as usual, or that the
 *    upstream has truncated its iprop log such that the ipropd-slave instance
 *    cannot perform incremental propagation and instead must receive a full
 *    HDB from the upstream
 *
 * Split-brain recovery:
 *
 *  - whenever ipropd-slave connects to an upstream, if the upstream has not
 *    truncated its local iprop log so as to force a full HDB send, then
 *    ipropd-slave continues as normal and split-brain recovery will be
 *    automatic
 *
 *  - if a full HDB send/receive is triggered, then ipropd-slave will apply
 *    every HDB entry received to the local HDB using the same infinite loop
 *    avoidance and conflict resolution algorithms as above
 *
 *    i.e., a full HDB send will be treated the same was as an iprop log of all
 *    the entries in the HDB
 *
 *  - local iprop log entries for full HDB receives will be written, causing
 *    downstream KDCs to get a full HDB prop (the receiving ipropd-slave can't
 *    truncate the local iprop log without triggering a storm of full props,
 *    though that could be an option)
 *
 * Operational semantics:
 *
 *  - any topology is supported where updates can flow from any one KDC to any
 *    other
 *
 *  - full meshes are not ideal owing to their O(N^2) network utilization
 *
 *  - KDCs should be configured to have enough local storage for several times
 *    the size of the HDB (1x for the HDB itself, 1x for a dump for sending to
 *    peer KDCs, 1x or 2x for the local iprop log, and a healthy amount of
 *    space for growth, so say 10x, which today is not a big deal at all)
 *
 *  - full iprop log truncation should be avoided, as writes will be
 *    unavailable during split-brain recovery if a full iprop log truncation
 *    happens during a split-brain event
 *
 *  - competing concurrent writes to the same entry at different KDCs will
 *    cause one of them to be lost non-deterministically, and different KDCs
 *    can reach stable contents where the affected principals have different
 *    HDB entries
 *
 *    Recovery from this is easy: perform the operations again but in sequence
 *    and at the same KDC, or on different KDCs but with the second operation
 *    being performed after the first has replicated.
 *
 * Future enhancements:
 *
 *  - better conflict resolution:
 *
 *     - write a description of the kadm5 write operation as an HDB extension
 *       in each HDB entry, thus allowing competing concurrent writes that make
 *       different changes to co-exist
 *
 *       The main use-case would be to allow the attributes of a principal to
 *       be altered in ways that resolve naturally and which do not compete
 *       with updates of a principal's kvno/key sets or other extensions.
 *
 *       This is probably overkill.
 *
 *  - automatic reconfiguration of iprop topology
 *
 *     - since we now have a way to store configurations in the HDB, we could
 *       store the iprop topology in the HDB itself, and upon receipt of an
 *       update of the iprop topology ipropd-slave could run a program that
 *       will stop/start iprop daemons as appropriate
 *
 *  - automatic iprop topology construction
 *
 *     - having knowledge of network topology as a set of sites, each with a
 *       set of KDCs, we could compute an iprop topology at some designated KDC
 *       which would then update the iprop configuration in the HDB and flow
 *       that to all the others using the current iprop topology, thus enabling
 *       automatic reconfiguration of the iprop topology for the entire realm
 *
 *     - the obvious topology would be a star topology within each site, and a
 *       star or ring topology between sites
 *
 *  - leader elections within sites to recover from leader unavailability
 *
 *     - each site would have to have its own configuration entry in the HDB to
 *       avoid conflict resolution issues when multiple sites have concurrent
 *       election events
 *
 *     - all other changes to the iprop topology (e.g., adding or removing
 *       sites or KDCs) would have to be manually performed at a desginated KDC
 *
 * Automatic iprop topology computation and reconfiguration would be a killer
 * feature for administration.
 */

static const char *config_name = "ipropd-slave";

static int verbose;
static int async_hdb = 0;
static int no_keytab_flag;
static int multi_master_flag;
static char *ccache_str;
static char *keytab_str;

static krb5_log_facility *log_facility;
static char five_min[] = "5 min";
static char *server_time_lost = five_min;
static int time_before_lost;
static char *local_hostname_str;
static KDC_Name local_KDC_name;
static const char *master_name;
static const char *connect_to;
static const char *pidfile_basename;
static char *realm;

/*
 * TODO:
 *
 *  - Clean things up and make this more library-like by getting rid of globals
 *    and collect all configuration values that we constantly pass around to
 *    functions into a configuration structure.
 */

#define EX_NOEXEC       126
#define EX_NOTFOUND     127

static void
hook(krb5_context context,
     const char *master,
     const char *event,
     const char *fmt,
     ...)
{
    static char **hook_argv;
    static size_t nhook;
    char **a;
    va_list ap;
    size_t i;
    char *s = NULL;
    int ret;

    if (hook_argv == NULL)
        hook_argv = krb5_config_get_strings(context, NULL, "kdc",
                                            "iprop_exec_hook", NULL);
    if (hook_argv == NULL) {
        hook_argv = calloc(1, sizeof(hook_argv[0]));
        for (nhook = 0; hook_argv[nhook]; nhook++)
            ;
        return;
    }
    if (nhook == 0)
        return;

    a = calloc(nhook + 3, sizeof(a[0]));
    va_start(ap, fmt);
    if (vasprintf(&s, fmt, ap) == -1 || s == NULL || a == NULL)
        krb5_err(context, 1, errno, "Executing iprop_exec_hook (%s)", hook_argv[0]);
    va_end(ap);
    for (i = 0; hook_argv[i] && i < nhook; i++)
        a[i] = hook_argv[i];
    hook_argv[i++] = rk_UNCONST(event);
    hook_argv[i++] = s;
    hook_argv[i] = NULL;
    switch ((ret = simple_execvp(a[0], a))) {
    case SE_E_UNSPECIFIED:
        krb5_warn(context, errno, "Could not exec iprop_exec_hook");
        break;
    case SE_E_FORKFAILED:
        krb5_warn(context, errno, "Could not exec iprop_exec_hook "
                  "(fork failed)");
        break;
    case SE_E_WAITPIDFAILED:
        krb5_warn(context, errno, "Could not exec iprop_exec_hook "
                  "(waitpid failed");
        break;
    case EX_NOTFOUND:
        errno = ENOENT;
        krb5_warn(context, errno, "Could not exec iprop_exec_hook "
                  "(exec failed)");
        break;
    case EX_NOEXEC:
        krb5_warnx(context, "Could not exec iprop_exec_hook "
                  "(exec failed");
        break;
    case 0:
        if (verbose)
            krb5_warnx(context, "iprop_exec_hook (%s %s) succeeded", a[0], s);
        break;
    default:
        krb5_warnx(context, "iprop_exec_hook (%s %s) failed: %d", a[0], s, ret);
    }
    krb5_config_free_strings(hook_argv);
    free(s);
    free(a);
}

static int
connect_to_master (krb5_context context, const char *master,
		   const char *port_str)
{
    char port[NI_MAXSERV];
    struct addrinfo *ai, *a;
    struct addrinfo hints;
    int error;
    int one = 1;
    int s = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    if (port_str == NULL) {
	snprintf(port, sizeof(port), "%u", IPROP_PORT);
	port_str = port;
    }

    error = getaddrinfo(master, port_str, &hints, &ai);
    if (error) {
	krb5_warnx(context, "Failed to get address of to %s: %s",
		   master, gai_strerror(error));
	return -1;
    }

    for (a = ai; a != NULL; a = a->ai_next) {
	char node[NI_MAXHOST];
	error = getnameinfo(a->ai_addr, a->ai_addrlen,
			    node, sizeof(node), NULL, 0, NI_NUMERICHOST);
	if (error)
	    strlcpy(node, "[unknown-addr]", sizeof(node));

	s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (s < 0)
	    continue;
	if (connect(s, a->ai_addr, a->ai_addrlen) < 0) {
	    krb5_warn(context, errno, "connection failed to %s[%s]",
		      master, node);
	    close(s);
	    continue;
	}
	krb5_warnx(context, "connection successful "
		   "to master: %s[%s]", master, node);
	break;
    }
    freeaddrinfo(ai);

    if (a == NULL)
	return -1;

    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) < 0)
        krb5_warn(context, errno, "setsockopt(SO_KEEPALIVE) failed");

    /*
     * We write message lengths separately from the payload, avoid Nagle
     * delays.
     */
#if defined(IPPROTO_TCP) && defined(TCP_NODELAY)
    (void) setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                      (void *)&one, sizeof(one));
#endif

    return s;
}

static void
get_creds(krb5_context context, krb5_ccache *cache, const char *serverhost)
{
    krb5_keytab keytab;
    krb5_principal client;
    krb5_error_code ret;
    krb5_get_init_creds_opt *init_opts;
    krb5_creds creds;
    char *server;
    char keytab_buf[256];
    int aret;

    if (no_keytab_flag) {
        /* We're using an externally refreshed ccache */
        if (*cache == NULL) {
            if (ccache_str == NULL)
                ret = krb5_cc_default(context, cache);
            else
                ret = krb5_cc_resolve(context, ccache_str, cache);
            if (ret)
                krb5_err(context, 1, ret, "Could not resolve the default cache");
        }
        return;
    }

    if (keytab_str == NULL) {
	ret = krb5_kt_default_name (context, keytab_buf, sizeof(keytab_buf));
	if (ret == 0) {
            keytab_str = keytab_buf;
        } else {
	    krb5_warn(context, ret, "Using HDBGET: as the default keytab");
            keytab_str = "HDBGET:";
        }
    }

    if (*cache)
        krb5_cc_destroy(context, *cache);
    *cache = NULL;

    ret = krb5_kt_resolve(context, keytab_str, &keytab);
    if(ret)
	krb5_err(context, 1, ret, "%s", keytab_str);

    ret = krb5_sname_to_principal(context, local_hostname_str, IPROP_NAME,
                                  KRB5_NT_SRV_HST, &client);
    if (ret) krb5_err(context, 1, ret, "krb5_sname_to_principal");
    if (local_hostname_str == NULL)
        local_hostname_str =
            strdup(krb5_principal_get_comp_string(context, client, 1));
    if (realm)
        ret = krb5_principal_set_realm(context, client, realm);
    if (ret) krb5_err(context, 1, ret, "krb5_principal_set_realm");

    ret = krb5_get_init_creds_opt_alloc(context, &init_opts);
    if (ret) krb5_err(context, 1, ret, "krb5_get_init_creds_opt_alloc");

    aret = asprintf (&server, "%s/%s", IPROP_NAME, serverhost);
    if (aret == -1 || server == NULL)
	krb5_errx (context, 1, "malloc: no memory");

    ret = krb5_get_init_creds_keytab(context, &creds, client, keytab,
				     0, server, init_opts);
    free (server);
    krb5_get_init_creds_opt_free(context, init_opts);
    if(ret) krb5_err(context, 1, ret, "krb5_get_init_creds");

    ret = krb5_kt_close(context, keytab);
    if(ret) krb5_err(context, 1, ret, "krb5_kt_close");

    ret = krb5_cc_new_unique(context, krb5_cc_type_memory, NULL, cache);
    if(ret) krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_cc_initialize(context, *cache, creds.client);
    if(ret) krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_store_cred(context, *cache, &creds);
    if(ret) krb5_err(context, 1, ret, "krb5_cc_store_cred");

    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, client);
}

static krb5_error_code
ihave(krb5_context context,
      const char *master,
      krb5_auth_context auth_context,
      int fd,
      uint32_t version,
      uint32_t tstamp)
{
    int ret;
    u_char buf[8];
    krb5_storage *sp;
    krb5_data data;

    sp = krb5_storage_from_mem(buf, 8);
    if (sp == NULL)
        krb5_err(context, IPROPD_RESTART_SLOW, ENOMEM, "Out of memory");
    ret = krb5_store_uint32(sp, I_HAVE);
    if (ret == 0)
        ret = krb5_store_uint32(sp, version);
    if (ret == 0)
        ret = krb5_store_uint32(sp, tstamp);
    krb5_storage_free(sp);
    data.length = 8;
    data.data   = buf;

    hook(context, master, "I_HAVE", "%"PRIu32" %"PRIu32, version, tstamp);

    if (ret == 0) {
        if (verbose)
            krb5_warnx(context, "telling master we are at %u", version);

        ret = krb5_write_priv_message(context, auth_context, &fd, &data);
        if (ret)
            krb5_warn(context, ret, "krb5_write_message");
    }
    return ret;
}

#ifndef EDQUOT
/* There's no EDQUOT on WIN32, for example */
#define EDQUOT ENOSPC
#endif

static int
key_in_keyset(Key *key, Keys *keys, int *probably_eq_sets)
{
    size_t i;

    for (i = 0; i < keys->len; i++) {
        /* Don't bother comparing salts */
        if (key->key.keytype != keys->val[i].key.keytype)
            continue;
        if (key->key.keyvalue.length != keys->val[i].key.keyvalue.length)
            continue;
        if (memcmp(key->key.keyvalue.data, keys->val[i].key.keyvalue.data,
                   keys->val[i].key.keyvalue.length) != 0)
            continue;
        if (i == 0)
            *probably_eq_sets = 1;
        return 1;
    }
    return 0;
}

static HDB_Ext_IPropInfo *
get_iprop_info(HDB_entry *ent)
{
    HDB_extension *ep;

    ep = hdb_find_extension(ent, choice_HDB_extension_data_iprop_info);
    if (ep)
        return &ep->data.u.iprop_info;
    return NULL;
}

/* Check if _this_ KDC is on the seen_kdcs list of the given iprop info */
static int
drop_entry_p(HDB_Ext_IPropInfo *ipi)
{
    size_t i;

    if (ipi == NULL)
        return 0;
    if (strcmp(ipi->last_mod_kdc, local_hostname_str) == 0)
        return 1;
    for (i = 0; i < ipi->seen_kdcs.len; i++)
        if (strcmp(local_hostname_str, ipi->seen_kdcs.val[i]) == 0)
            return 1;
    return 0;
}

/*
 * Merge two keysets.  See call site.
 *
 * NOTE: We only merge the current keysets.
 */
static krb5_error_code
merge_keysets(krb5_context context,
              HDB_entry *resolved,
              HDB_entry *left,
              HDB_entry *right,
              int *touched)
{
    krb5_error_code ret = 0;
    Keys *lk = &left->keys;
    Keys *rk = &right->keys;
    size_t i;

    /* Merge keysets.  This will be O(N^2), but with a bound. */
    if (rk->len < 8) {
        int probably_eq_sets = 0;

        /*
         * Heuristic: if the keysets start with the same key and have the same
         * length, they are probably the same, so there's nothing to be done.
         */
        for (i = 0; ret == 0 && i < rk->len && i < 8; i++) {
            if (key_in_keyset(&rk->val[i], rk, &probably_eq_sets)) {
                if (i == 0 && probably_eq_sets && lk->len == rk->len)
                    break;
                continue;
            }
            ret = add_Keys(&resolved->keys, &rk->val[i]);
            if (touched)
                *touched = 1;
        }
    }
    return ret;
}

/*
 * Set a resolved HDB entry's iprop info, which mainly means adding the local
 * KDC's name to the seen_kdcs list in the entry's iprop info.
 */
static krb5_error_code
update_iprop_info(krb5_context context,
                  const char *origin_kdc,
                  KerberosTime last_mod_time,
                  HDB_entry *resolved,
                  HDB_Ext_IPropInfo *upstream)
{
    krb5_error_code ret;
    HDB_extension *ep;
    HDB_extension e;

    memset(&e, 0, sizeof(e));

    /*
     * For interop with older ipropd-master instances we try to impute the
     * upstream entry's missing iprop_info.
     */
    if (upstream) {
        e.data.u.iprop_info = *upstream;

        /* Default things that should be set already */
        if (e.data.u.iprop_info.last_mod_kdc == NULL)
            e.data.u.iprop_info.last_mod_kdc = rk_UNCONST(origin_kdc);
        if (e.data.u.iprop_info.last_mod_kdc_time == 0)
            e.data.u.iprop_info.last_mod_kdc_time = last_mod_time;
    } else {
        /* Our upstream is older and didn't set the iprop info */
        e.data.u.iprop_info.last_mod_kdc_time = last_mod_time;
        e.data.u.iprop_info.last_mod_kdc = rk_UNCONST(origin_kdc);
        e.data.u.iprop_info.seen_kdcs.val = NULL;
        e.data.u.iprop_info.seen_kdcs.len = 0;
    }
    e.data.element = choice_HDB_extension_data_iprop_info;

    ret = hdb_replace_extension(context, resolved, &e);
    if (ret)
        return ret;

    /* Recall: hdb_replace_extension() copies the extension */
    ep = hdb_find_extension(resolved, e.data.element);
    if (ep == NULL)
        return EINVAL; /* Doesn't happen */

    /*
     * XXX We should make sure to insert in order so that we can binary search
     * this.  If we don't do this before shipping, then we can't really do it.
     */
    ret = add_IPropInfo_Seen_KDCs(&ep->data.u.iprop_info.seen_kdcs,
                                  &local_KDC_name);
    return ret;
}

/*
 * Given an upstream entry, and possibly a local entry, pick a winner if there
 * is a local entry, check if this upstream update should be dropped, and edit
 * its iprop info's KDCs seen list to note this node has seen this entry.
 *
 * If `*drop' is set to 0, then `*resolved' will be initialized with an entry
 * that must be stored and then freed by the caller.  Else `*resolved' must not
 * be used by the caller.
 */
static krb5_error_code
resolve_conflict(krb5_context context,
                 kadm5_server_context *local_context,
                 enum kadm_ops op,
                 const char *upstream_name,
                 hdb_entry *upstream,
                 hdb_entry *existing,
                 int *drop,
                 hdb_entry *resolved)
{
    krb5_error_code ret;
    HDB_Ext_IPropInfo *ipi_upstream = get_iprop_info(upstream);
    hdb_entry *winner = upstream;
    KerberosTime tupstream; /* Last modify time of upstream entry */
    const char *origin_kdc = upstream_name;
    struct hdb_uuid_string uuid_e, uuid_u;
    int origin_kdc_cmp = 0;
    int touched = 0;

    *drop = 0;
    memset(resolved, 0, sizeof(*resolved));
    uuid_e.s[0] = uuid_u.s[0] = '\0';
    if (verbose > 1) {
        if (existing)
            uuid_e = hdb_entry_get_tx_uuid_string(existing);
        else
            strlcpy(uuid_e.s, "<no-local-entry>", sizeof(uuid_e.s));
        uuid_u = hdb_entry_get_tx_uuid_string(upstream);
        krb5_warnx(context,
                   "Resolving conflict between %s (local) and %s (upstream)",
                   uuid_e.s, uuid_u.s);
    }

    /*
     * Transaction time preference hierarchy:
     *  - last_mod_kdc_time from iprop info is best
     *  - modified_by->time is next bext
     *  - created_by->time is last
     */
    tupstream = upstream->created_by.time;
    if (upstream->modified_by)
        tupstream = upstream->modified_by->time;

    /*
     * Drop entries that we have already seen.
     *
     * If we don't drop this then we'll add this KDC's name to the list before
     * storing the resolved entry into the HDB.
     *
     * Not dropping this update would cause to to circulate endlessly -- an
     * infinite loop that would melt the network.
     */
    if ((*drop = drop_entry_p(ipi_upstream)))
        return 0;

    if (ipi_upstream) {
        /* Use last-modified KDC name and time from iprop info extension */
        origin_kdc = ipi_upstream->last_mod_kdc;
        tupstream = ipi_upstream->last_mod_kdc_time;
    }

    /*
     * If we have a conflict, pick a winner and resolve the conflict
     *
     * For deletes from the upstream the upstream always wins (`winner' is
     * already initialized to `upstream').  We won't be writing the [bogus]
     * HDB_entry from the upstream to the HDB anyways.
     */
    if (existing && op != kadm_delete) {
        HDB_Ext_IPropInfo *ipi_existing;
        KerberosTime texisting = existing->created_by.time;
        const char *last_mod_kdc_existing = local_hostname_str;

        /* Pick a winner */
        ipi_existing = get_iprop_info(existing);
        if (ipi_existing)
            last_mod_kdc_existing = ipi_existing->last_mod_kdc;

        /* Get the best possible time */
        if (existing->modified_by)
            texisting = existing->modified_by->time;
        if (ipi_existing && ipi_existing->last_mod_kdc_time > texisting)
            texisting = ipi_existing->last_mod_kdc_time;

        /* This will be a tie-breaker */
        origin_kdc_cmp = strcmp(last_mod_kdc_existing, origin_kdc);
        if (origin_kdc_cmp == 0 && texisting > tupstream) {
            /*
             * We're hearing of an older entry from the same origin via a peer
             * KDC that is behind us, so drop it.  We assume monotonic clocks
             * on each KDC.
             *
             * Thus we can end up missing this particular update entirely, but
             * since we took a later, full HDB entry from the same origin,
             * missing an intermediate change from the same origin KDC is fine.
             */
            *drop = 1;
            return 0;
        }

        /*
         * So we're going to resolve the conflict rather than drop the upstream
         * iprop entry.  We need to pick one to prefer.
         *
         * Maybe we should allow for a bit more skew here and treat
         * |texisting - tupstream| < 5s as == and then use tie-breakers.
         *
         * Also, whichever has the highest kvno should win, but! if you look at
         * kadmin/ank.c you'll see that when kadmin creates a principal, first
         * it creates it locked, then it randomizes the keys, then it unlocks
         * the principal _and_ sets the kvno _back_ one!  So we can't just say
         * that the highest kvno wins.
         *
         * Maybe we should revisit what kadmin/ank.c does, but not today as
         * there are tools that expect kvnos to start at 1.
         *
         * Still, if either kvno is larger than 2 and one is larger than the
         * other, then the larger kvno wins.
         */

        if ((existing->kvno > 2 || upstream->kvno > 2) &&
            existing->kvno != upstream->kvno) {
            if (existing->kvno > upstream->kvno) {
                winner = existing;
                if (verbose > 1)
                    krb5_warnx(context,
                               "Picking local %s over upstream %s (%s) "
                               "using kvno", uuid_e.s, uuid_u.s, origin_kdc);
            } else {
                winner = upstream;
                if (verbose > 1)
                    krb5_warnx(context,
                               "Picking upstream %s (%s) over local %s "
                               "using kvno", uuid_u.s, uuid_e.s, origin_kdc);
            }
        } else if (texisting > tupstream) {
            winner = existing;
            if (verbose > 1)
                krb5_warnx(context, "Picking local %s over upstream %s (%s) "
                           "using, last-modify time", uuid_e.s, uuid_u.s,
                           origin_kdc);
        } else if (texisting < tupstream) {
            winner = upstream;
            if (verbose > 1)
                krb5_warnx(context, "Picking upstream %s (%s) over local %s "
                           "using last-modify time", uuid_u.s, uuid_e.s,
                           origin_kdc);
        } else if (origin_kdc_cmp < 0) {
            winner = existing;
            if (verbose > 1)
                krb5_warnx(context, "Picking local %s over upstream %s (%s) "
                           "using origin name as tie breaker",
                           uuid_e.s, uuid_u.s, origin_kdc);
        } else {
            winner = upstream;
            if (verbose > 1)
                krb5_warnx(context, "Picking upstream %s (%s) over local %s "
                           "using origin name as tie breaker",
                           uuid_u.s, uuid_e.s, origin_kdc);
        }
    } else {
        /*
         * Else no conflict, and we didn't choose to drop the entry either, so
         * we'll just take it.
         */
        if (verbose > 1 && op == kadm_delete)
            krb5_warnx(context, "Picking upstream deletion %s (%s)",
                       uuid_u.s, origin_kdc);
    }

    /*
     * If we have an existing entry then we have a conflict.  Merge the two
     * into a copy of the winner (we don't mutate the entries handed to us).
     */
    ret = copy_HDB_entry(winner, resolved);
    if (ret == 0 && op != kadm_delete && existing &&
        existing->kvno == upstream->kvno && origin_kdc_cmp) {
        /*
         * Merge keysets if same kvno from different upstreams.
         *
         * A transaction can add or remove keys from the default keyset w/o
         * changing the kvno -- this is mostly just for kadmin del_enctype, to
         * delete keys of weak enctypes, say.  We if we get a transaction that
         * changes the keys, but leaves the kvno alone, and the origin of the
         * entries is the same, we leave the keyset alone.
         */
        if (winner == upstream) {
            ret = merge_keysets(context, resolved, existing, upstream, NULL);
            touched = 1;
        } else {
            ret = merge_keysets(context, resolved, upstream, existing,
                                &touched);
        }
    }
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret,
                 "Could not resolve conflict");

    if (winner == existing && !touched) {
        /*
         * Local entry wins _and_ nothing was done to resolve the conflict, so
         * we don't propagate this upstream entry any further by just dropping
         * it.
         */
        *drop = 1;
        return 0; /* FYI the caller frees the resolved entry */
    }
    if (verbose > 1)
        krb5_warnx(context, "Picked %s (%s) %s merged keysets",
                   winner == existing ? "local" : "upstream",
                   winner == existing ? uuid_e.s : uuid_u.s,
                   touched ? "with" : "without");

    /*
     * Whether we took the upstream entry as-is, or merged it with the local
     * entry, we must allow this to further propagate, so we must set the
     * resolved entry's iprop info to the upstream entry's info, and we must
     * add this KDC to the seen_kdcs sequence.
     *
     * This allows any merging done here to propagate even if the winning
     * principal was the local one, and also prevents endless cycling of iprop
     * records because we're using the upstream iprop info rather than
     * pretending this is a new transaction originated here.
     */
    ret = update_iprop_info(context, upstream_name, tupstream, resolved,
                            ipi_upstream);
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret,
                 "Could not resolve conflict");
    return 0;
}

static krb5_error_code
get_entry(krb5_context context,
          krb5_storage *sp,
          size_t len,
          hdb_entry *entry,
          int optional)
{
    krb5_error_code ret;
    krb5_data value;
    krb5_ssize_t bytes;

    if (len == 0) {
        if (optional)
            return 0;

        krb5_warnx(context,
                   "Truncated iprop create or modify entry received");
        return HEIM_ERR_EOF;
    }
    value.length = len;
    if ((value.data = malloc(len)) == NULL)
        krb5_err(context, IPROPD_RESTART_SLOW, ENOMEM, "Could not read HDB");
    bytes = krb5_storage_read(sp, value.data, len);
    if (bytes < 0) {
        krb5_warnx(context,
                   "Truncated iprop create or modify entry received");
        free(value.data);
        return 0;
    }

    ret = hdb_value2entry(context, &value, entry);
    if (ret) {
        krb5_warn(context, ret, "Could not parse HDB entry from upstream");
        free(value.data);
        return ret;
    }
    free(value.data);
    return 0;
}

static char *
princ_str(krb5_context context, krb5_principal p, hdb_entry *e)
{
    krb5_error_code ret;
    char *ps = NULL;
    char *s = NULL;

    if (!p && e->principal)
        p = e->principal;
    if (!p)
        return strdup("<unknown-principal>");
    ret = krb5_unparse_name(context, p, &ps);
    if (ret)
        return strdup("<error-unparsing-principal>");
    if (rk_strasvis(&s, ps, 0, "") == -1)
        ret = errno;
    krb5_xfree(ps);
    if (ret == 0)
        return s;
    return strdup("<error-escaping-principal>");
}

/* Multi-master alternative to single-mastered append_to_log_file() */
static krb5_error_code
apply_iprop_entry(krb5_context context,
                  kadm5_server_context *local_context,
                  const char *master,
                  krb5_storage *sp,
                  enum kadm_ops op,
                  off_t start,
                  uint32_t len)
{
    krb5_error_code ret;
    krb5_principal p = NULL;
    hdb_entry entry;    /* from upstream */
    hdb_entry existing; /* local entry */
    hdb_entry resolved; /* conflict resolved */
    uint32_t mask = 0;
    off_t off;
    char *ps1 = NULL;
    char *ps2 = NULL;
    int drop = 0;
    int found_existing;

    memset(&entry, 0, sizeof(entry));
    resolved = existing = entry;

    switch (op) {
    case kadm_nop:
        /*
         * NOTE: We can't apply NOPs as they don't carry an HDB_entry, so no
         *       IPropInfo.  Without the IPropInfo, if we apply an upstream's
         *       nop to our local log then it would circulate forever in a
         *       multi-master setup.  We can't exactly add IPropInfo to NOPs
         *       either.
         */
        if (verbose)
            krb5_warnx(context, "Ignoring a NOP from %s", master_name);
        return 0; /* It's a nop -a no-op-, so nothing to do here */
    default:
        krb5_warnx(context, "Unsupported iprop log entry operation %d from %s",
                   op, master_name);
        return 0;
    case kadm_create:
        break;
    case kadm_modify:
        /*
         * Modifies are first a mask of KADM5 things changed, then an encoded
         * HDB_entry.
         */
        ret = krb5_ret_uint32(sp, &mask);
        if (ret) {
            krb5_warn(context, ret,
                      "Could not read mask from modify entry");
            return ret;
        }
        break;
    case kadm_delete:
    case kadm_rename:
        /* Deletes and renames have an old principal name first */
        ret = krb5_ret_principal(sp, &p);
        if (ret) {
            krb5_warn(context, ret,
                      "Could not read principal name from rename entry");
            return ret;
        }
        break;
    }

    off = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (off < 0) {
        krb5_warnx(context, "Could not read rename entry");
        return 0;
    }
    if (off < start)
        /*
         * Can't happen -- just help the compiler understand that off -
         * start is positive.
         */
        abort();
    len -= (uint32_t)(off - start);

    /*
     * We handle creates, modifies, and renames the same way since we could
     * hear about related events for one principal out of order because
     * they might happen on different KDCs that sync up before this one.
     *
     * For modifies we could maybe use the mask of kadm5 things modified so
     * we could be a wee bit more intelligent about what we take from the
     * local and upstream entries.  But really, we want an HDB_entry
     * extension that tells us a little more about the deltas: maybe one
     * modify added an attribute while another removed an attribute, and
     * those two transactions trivially merge.  Anyways, not today.
     */

    ret = get_entry(context, sp, len, &entry, op == kadm_delete);
    if (ret == HEIM_ERR_EOF)
        /* We've warned in get_entry(); continue processing entries */
        return 0;
    if (ret) {
        krb5_warn(context, ret, "Could not read HDB entry from iprop record");
        return 0;
    }

    ps1 = princ_str(context, p, &entry);
    if (ps1 == NULL)
        krb5_errx(context, IPROPD_RESTART_SLOW, "Out of memory");

    /*
     * In multi-master mode only hold an exclusive lock on the local iprop log
     * and HDB while applying iprop entries.  We start by reading the old entry
     * from the local HDB with the lock held, then we resolve conflicts, then
     * we log the conflict-resolved entry unless we want to drop it.
     */
    ret = kadm5_log_exclusivelock(local_context);
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret,
                 "Could not lock HDB and iprop log");

    /*
     * For deletes and renames, use the principal read earlier.  For creates
     * and modifies, use the principal name from the entry we read.
     */
    ret = hdb_fetch_kvno(context, local_context->db,
                         p ? p : entry.principal,
                         HDB_F_DECRYPT |
                         HDB_F_GET_ANY |
                         HDB_F_ADMIN_DATA,
                         0, 0, 0, &existing);
    if (ret != 0 && ret != HDB_ERR_NOENTRY)
        krb5_err(context, IPROPD_RESTART_SLOW, ret, "Could not read HDB");
    found_existing = ret == 0;

    /*
     * Resolve conflicts, decide whether to drop this iprop record, edit the
     * entry's iprop metadata, encode it into `resolved' so we can write it to
     * the log and the HDB.
     */
    ret = resolve_conflict(context, local_context, op, master, &entry,
                           found_existing ? &existing : NULL,
                           &drop, &resolved);
    if (ret == 0) {
        struct hdb_uuid_string uuid = hdb_entry_get_tx_uuid_string(&resolved);

        /*
         * If (drop) we could write the resolved entry to the HDB, but we should
         * not write it to the local iprop log or we would propagate it more
         * than is necessary. For now we don't even write it to the HDB.
         */
        switch (op) {
        case kadm_create:
            if (drop) {
                krb5_warnx(context, "Dropping a create from %s of %s (%s)",
                           master, ps1, uuid.s);
                /* ret = kadm5_log_nop(local_context, kadm_nop_plain); */
            } else {
                if (verbose)
                    krb5_warnx(context, "Applying a create from %s of %s (%s)",
                               master, ps1, uuid.s);
                ret = kadm5_log_create(local_context, &resolved);
                if (ret)
                    krb5_warnx(context,
                               "Failed to apply a create from %s of %s (%s)",
                               master, ps1, uuid.s);
            }
            break;
        case kadm_modify:
            if (drop) {
                krb5_warnx(context, "Dropping a modify from %s of %s (%s)",
                           master, ps1, uuid.s);
            } else {
                if (verbose)
                    krb5_warnx(context, "Applying a modify from %s of %s (%s)",
                               master, ps1, uuid.s);
                ret = kadm5_log_modify(local_context, &resolved, mask);
                if (ret)
                    krb5_warnx(context,
                               "Failed to apply a modify from %s of %s (%s)",
                               master, ps1, uuid.s);
            }
            break;
        case kadm_rename:
            ps2 = princ_str(context, NULL, &entry);
            if (ps2 == NULL)
                krb5_errx(context, IPROPD_RESTART_SLOW, "Out of memory");
            if (drop) {
                krb5_warnx(context,
                           "Dropping a rename from %s of %s to %s (%s)",
                           master, ps1, ps2, uuid.s);
            } else {
                if (verbose)
                    krb5_warnx(context,
                               "Applying a rename from %s of %s to %s (%s)",
                               master, ps1, ps2, uuid.s);
                ret = kadm5_log_rename(local_context, p, &resolved);
                if (ret)
                    krb5_warnx(context,
                               "Failed to apply a rename from %s of %s to %s "
                               "(%s)", master, ps1, ps2, uuid.s);
            }
            break;
        case kadm_delete:
            if (drop) {
                krb5_warnx(context, "Dropping a delete from %s of %s (%s)",
                           master, ps1, uuid.s);
            } else {
                if (verbose)
                    krb5_warnx(context, "Applying a delete from %s of %s (%s)",
                               master, ps1, uuid.s);
                ret = kadm5_log_delete(local_context, p, &resolved);
                if (ret)
                    krb5_warnx(context,
                               "Failed to apply a delete from %s of %s (%s)",
                               master, ps1, uuid.s);
            }
            break;
        default:
            break; /* Already handled above dear compiler */
        }
    } else {
        krb5_warn(context, ret, "Failed to resolve conflict");
    }

    (void) kadm5_log_unlock(local_context);
    hdb_free_entry(context, local_context->db, &resolved);
    hdb_free_entry(context, local_context->db, &existing);
    hdb_free_entry(context, local_context->db, &entry);
    krb5_free_principal(context, p);
    rk_xfree(ps1);
    rk_xfree(ps2);
    return ret;
}

/*
 * append_to_log_file() is for the single-master case.  We append to the log
 * the entries sent by the server, then our caller will call
 * kadm5_log_recover() to replay the entries.
 *
 * See apply_iprop_entry() for the multi-master alternative.
 */
static int
append_to_log_file(krb5_context context,
                   kadm5_server_context *server_context,
                   krb5_storage *sp, off_t start, ssize_t slen)
{
    size_t len;
    ssize_t sret;
    off_t log_off;
    int ret, ret2;
    void *buf;

    if (verbose)
        krb5_warnx(context, "appending diffs to log");

    if (slen == 0)
        return 0;
    if (slen < 0)
        return EINVAL;
    len = slen;
    if (len != slen)
        return EOVERFLOW;

    buf = malloc(len);
    if (buf == NULL && len != 0)
	return krb5_enomem(context);

    if (krb5_storage_seek(sp, start, SEEK_SET) != start) {
        krb5_errx(context, IPROPD_RESTART,
                  "krb5_storage_seek() failed"); /* can't happen */
    }
    sret = krb5_storage_read(sp, buf, len);
    if (sret < 0)
        return errno;
    if (len != (size_t)sret) {
        /* Can't happen */
        krb5_errx(context, IPROPD_RESTART,
                  "short krb5_storage_read() from memory buffer");
    }
    log_off = lseek(server_context->log_context.log_fd, 0, SEEK_CUR);
    if (log_off == -1)
        return errno;

    /*
     * Use net_write() so we get an errno if less that len bytes were
     * written.
     */
    sret = net_write(server_context->log_context.log_fd, buf, len);
    free(buf);
    if (sret != slen)
        ret = errno;
    else
        ret = fsync(server_context->log_context.log_fd);
    if (ret == 0)
        return 0;
    krb5_warn(context, ret,
              "Failed to write iprop log fd %d %llu bytes at offset %lld: %d",
              server_context->log_context.log_fd, (unsigned long long)len,
              (long long)log_off, ret);

    /*
     * Attempt to recover from this.  First, truncate the log file
     * and reset the fd offset.  Failure to do this -> unlink the
     * log file and re-create it.  Since we're the slave, we ought to be
     * able to recover from the log being unlinked...
     */
    if (ftruncate(server_context->log_context.log_fd, log_off) == -1 ||
        lseek(server_context->log_context.log_fd, log_off, SEEK_SET) == -1) {
        (void) kadm5_log_end(server_context);
        if (unlink(server_context->log_context.log_file) == -1) {
            krb5_err(context, IPROPD_FATAL, errno,
                     "Failed to recover from failure to write log "
                     "entries from master to disk");
        }
        ret2 = kadm5_log_init(server_context);
        if (ret2) {
            krb5_err(context, IPROPD_RESTART_SLOW, ret2,
                     "Failed to initialize log to recover from "
                     "failure to write log entries from master to disk");
        }
    }
    if (ret == ENOSPC || ret == EDQUOT || ret == EFBIG)
        krb5_err(context, IPROPD_RESTART_SLOW, ret,
                  "Failed to write log entries from master to disk");
    /*
     * All other errors we treat as fatal here.  This includes, for
     * example, EIO and EPIPE (sorry, can't log to pipes nor sockets).
     */
    krb5_err(context, IPROPD_FATAL, ret,
             "Failed to write log entries from master to disk");
}

static void reinit_log(krb5_context, kadm5_server_context *,
                       uint32_t, uint32_t);

static int
receive_loop_multi(krb5_context context,
                   const char *master,
                   krb5_storage *sp,
                   kadm5_server_context *server_context,
                   kadm5_server_context *local_context)
{
    int ret;
    off_t off;
    uint32_t len, vers, tstamp;

    if (verbose)
        krb5_warnx(context, "receiving diffs");

    ret = kadm5_log_exclusivelock(server_context);
    if (ret)
        krb5_err(context, IPROPD_RESTART, ret,
                 "Failed to lock iprop log for writes");

    /*
     * Seek to the first entry in the message from the master that is
     * past the current version of the local database.
     */
    do {
	uint32_t timestamp;
        uint32_t op;

        if ((ret = krb5_ret_uint32(sp, &vers)) == HEIM_ERR_EOF)
            break;
	if (ret ||
            (ret = krb5_ret_uint32(sp, &timestamp)) != 0 ||
            (ret = krb5_ret_uint32(sp, &op)) != 0 ||
            (ret = krb5_ret_uint32(sp, &len)) != 0) {

            /*
             * This shouldn't happen.  Reconnecting probably won't help
             * if it does happen, but by reconnecting we get a chance to
             * connect to a new master if a new one is configured.
             */
            krb5_warn(context, ret,
                      "iprop entries from upstream were truncated");
            return ret;
        }
        off = krb5_storage_seek(sp, 0, SEEK_CUR);

        hook(server_context->context, master, "FOR_YOU",
             "Merging incremental entry version %"PRIu32 " timestamp %"PRIu32
             "op %"PRIu32 " length %"PRIu32, vers, timestamp, op, len);

        /* XXX Also check the time, so we can protect against version rollover */
	if (vers > server_context->log_context.version) {
            ret = kadm5_log_get_version(local_context,
                                        &local_context->log_context.version,
                                        &local_context->log_context.last_time);
            if (ret)
                /* Warn but try anyways */
                krb5_warn(context, ret,
                          "failed to determine current version in local log %s",
                          local_context->log_context.log_file);
            ret = apply_iprop_entry(context, local_context, master, sp,
                                    op, off, len);
            if (ret)
                krb5_warn(context, ret, "failed to apply iprop entry %u (upstream)", vers);

            reinit_log(context, server_context, vers, timestamp);
        }
        if (krb5_storage_seek(sp, off + len + 8, SEEK_SET) != off + len + 8) {
            krb5_warnx(context, "iprop entries from master were truncated");
            return EINVAL;
        }
        if (verbose) {
            krb5_warnx(context, "diff contains old log record version "
                       "%u %lld %u length %u",
                       vers, (long long)timestamp, op, len);
        }
    } while (ret == 0);

    if (ret && ret == HEIM_ERR_EOF)
        return 0;

    ret = kadm5_log_get_version(server_context, &vers, &tstamp);
    if (ret) {
        krb5_warn(context, ret,
                  "could not get log version after applying diffs!");
        return ret;
    }
    if (verbose)
        krb5_warnx(context, "KDC at version %u", vers);

    if (vers != server_context->log_context.version) {
        krb5_warnx(context, "KDC's log_context version (%u) is "
                   "inconsistent with log's version (%u)",
                   server_context->log_context.version, vers);
    }

    return 0;
}

static int
receive_loop(krb5_context context,
             const char *master,
	     krb5_storage *sp,
	     kadm5_server_context *server_context)
{
    int ret;
    off_t left, right, off;
    uint32_t len, vers, tstamp;

    if (verbose)
        krb5_warnx(context, "receiving diffs");

    ret = kadm5_log_exclusivelock(server_context);
    if (ret)
        krb5_err(context, IPROPD_RESTART, ret,
                 "Failed to lock iprop log for writes");

    /*
     * Seek to the first entry in the message from the master that is
     * past the current version of the local database.
     */
    do {
	uint32_t timestamp;
        uint32_t op;

        if ((ret = krb5_ret_uint32(sp, &vers)) == HEIM_ERR_EOF) {
            krb5_warnx(context, "master sent no new iprop entries");
            return 0;
        }

        /*
         * TODO We could do more to validate the entries from the master
         * here.  And we could use/reuse more kadm5_log_*() code here.
         *
         * Alternatively we should trust that the master sent us exactly
         * what we needed and just write this to the log file and let
         * kadm5_log_recover() do the rest.
         *
         * This will happen, essentially, in the multi-master code.
         */
	if (ret ||
            (ret = krb5_ret_uint32(sp, &timestamp)) != 0 ||
            (ret = krb5_ret_uint32(sp, &op)) != 0 ||
            (ret = krb5_ret_uint32(sp, &len)) != 0) {

            /*
             * This shouldn't happen.  Reconnecting probably won't help
             * if it does happen, but by reconnecting we get a chance to
             * connect to a new master if a new one is configured.
             */
            krb5_warn(context, ret, "iprop entries from master were truncated");
            return ret;
        }

        /* XXX Also check the time, so we can protect against version rollover */
	if (vers > server_context->log_context.version) {
            break;
        }
        off = krb5_storage_seek(sp, 0, SEEK_CUR);
        if (krb5_storage_seek(sp, len + 8, SEEK_CUR) != off + len + 8) {
            krb5_warnx(context, "iprop entries from master were truncated");
            return EINVAL;
        }
        if (verbose) {
            krb5_warnx(context, "diff contains old log record version "
                       "%u %lld %u length %u",
                       vers, (long long)timestamp, op, len);
        }
    } while(vers <= server_context->log_context.version);

    hook(server_context->context, master, "FOR_YOU",
         "Applying incremental entries from version %"PRIu32, vers);

    /*
     * Read the remaining entries into memory...
     */
    /* SEEK_CUR is a header into the first entry we care about */
    left  = krb5_storage_seek(sp, -16, SEEK_CUR);
    right = krb5_storage_seek(sp, 0, SEEK_END);
    if (right - left < 24 + len) {
        krb5_warnx(context, "iprop entries from master were truncated");
        return EINVAL;
    }

    /*
     * ...and then write them out to the on-disk log.
     */

    ret = append_to_log_file(context, server_context, sp, left, right - left);
    if (ret)
        return ret;

    /*
     * Replay the new entries.
     */
    if (verbose)
        krb5_warnx(context, "replaying entries from master");
    ret = kadm5_log_recover(server_context, kadm_recover_replay);
    if (ret) {
        krb5_warn(context, ret, "replay failed");
        return ret;
    }

    ret = kadm5_log_get_version(server_context, &vers, &tstamp);
    if (ret) {
        krb5_warn(context, ret,
                  "could not get log version after applying diffs!");
        return ret;
    }
    if (verbose)
        krb5_warnx(context, "slave at version %u", vers);

    if (vers != server_context->log_context.version) {
        krb5_warnx(context, "slave's log_context version (%u) is "
                   "inconsistent with log's version (%u)",
                   server_context->log_context.version, vers);
    }

    return 0;
}

static int
receive(krb5_context context,
        const char *master,
        krb5_storage *sp,
        kadm5_server_context *server_context,
        kadm5_server_context *local_context)
{
    krb5_error_code ret, ret2;

    if (local_context) {
        HDB *mydb = local_context->db;
        ret = mydb->hdb_open(context, local_context->db, O_RDWR | O_CREAT, 0600);
        if (ret)
            krb5_err(context, IPROPD_RESTART_SLOW, ret, "db->open");

        (void) mydb->hdb_set_sync(context, mydb, !async_hdb);
        ret2 = receive_loop_multi(context, master, sp, server_context, local_context);
        if (ret2)
            krb5_warn(context, ret2, "receive from ipropd-master had errors");

        ret = mydb->hdb_close(context, local_context->db);
        if (ret)
            krb5_err(context, IPROPD_RESTART_SLOW, ret, "db->close");
    } else {
        HDB *mydb = server_context->db;

        ret = mydb->hdb_open(context, server_context->db, O_RDWR | O_CREAT, 0600);
        if (ret)
            krb5_err(context, IPROPD_RESTART_SLOW, ret, "db->open");

        (void) mydb->hdb_set_sync(context, mydb, !async_hdb);
        ret2 = receive_loop(context, master, sp, server_context);
        if (ret2)
            krb5_warn(context, ret2, "receive from ipropd-master had errors");

        ret = mydb->hdb_close(context, server_context->db);
        if (ret)
            krb5_err(context, IPROPD_RESTART_SLOW, ret, "db->close");
    }

    (void) kadm5_log_sharedlock(server_context);
    if (verbose)
        krb5_warnx(context, "downgraded iprop log lock to shared");

    /* For hierarchical and multi-master iprop */
    kadm5_log_signal_master(local_context ? local_context : server_context);
    if (verbose)
        krb5_warnx(context, "signaled master for hierarchical iprop");
    return ret2;
}

static void
send_im_here(krb5_context context, const char *master, int fd,
	     krb5_auth_context auth_context)
{
    krb5_storage *sp;
    krb5_data data;
    krb5_error_code ret;

    hook(context, master, "I_AM_HERE", "");

    ret = krb5_data_alloc(&data, 4);
    if (ret)
        krb5_err(context, IPROPD_RESTART, ret, "send_im_here");

    sp = krb5_storage_from_data (&data);
    if (sp == NULL)
        krb5_errx(context, IPROPD_RESTART, "krb5_storage_from_data");
    ret = krb5_store_uint32(sp, I_AM_HERE);
    krb5_storage_free(sp);

    if (ret == 0) {
        ret = krb5_write_priv_message(context, auth_context, &fd, &data);
        krb5_data_free(&data);

        if (ret)
            krb5_err(context, IPROPD_RESTART, ret, "krb5_write_priv_message");

        if (verbose)
            krb5_warnx(context, "pinged master");
    }

    return;
}

static void
reinit_log(krb5_context context,
	   kadm5_server_context *server_context,
	   uint32_t vno,
           uint32_t tstamp)
{
    krb5_error_code ret;

    if (verbose)
        krb5_warnx(context, "truncating log on slave");

    ret = kadm5_log_reinit(server_context, vno, tstamp);
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret, "kadm5_log_reinit");
    (void) kadm5_log_sharedlock(server_context);
    if (verbose)
        krb5_warnx(context, "downgraded iprop log lock to shared");
}

static void
update_last_time_seen(hdb_entry *e, uint32_t *last_time_seenp)
{
    HDB_Ext_IPropInfo *ipi = get_iprop_info(e);
    KerberosTime t;
    uint32_t tu;

    t = e->created_by.time;
    if (ipi)
        t = ipi->last_mod_kdc_time;
    else if (e->modified_by)
        t = e->modified_by->time;
    tu = t;
    if (t > 0 && *last_time_seenp < tu)
        *last_time_seenp = tu;
}

/*
 * This is the receive_everything variant for multi-master mode.
 *
 * If we get here in a multi-master setup and we have a non-empty local HDB,
 * it's because we've gotten into a split-brain situation for long enough that
 * the upstream had to truncate its iprop log and we now can't catch up.
 *
 * For multi-master we either don't want to accept full props, or if we do then
 * we really want to merge with the local HDB, not truncate it!
 */
static krb5_error_code
merge_everything(krb5_context context, const char *master, int fd,
                 kadm5_server_context *server_context,
                 kadm5_server_context *local_context,
                 krb5_auth_context auth_context)
{
    int ret;
    krb5_data data;
    uint32_t vno = 0;
    uint32_t tstamp = 0;
    uint32_t opcode;
    uint32_t last_time_seen = 0; /* In case the upstream is older and doesn't
                                  * tell us its last_time */
    krb5_storage *sp;
    HDB *mydb;

    hook(server_context->context, master, "TELL_YOU_EVERYTHING", "merge HDB");
    krb5_warnx(context, "receive complete database (multi-master)");
    ret = kadm5_log_exclusivelock(local_context);
    if (ret)
        krb5_err(context, IPROPD_RESTART, ret,
                 "Failed to lock iprop log for writes");
    ret = hdb_create(context, &mydb, local_context->db->hdb_name);
    if(ret)
        krb5_err(context, IPROPD_RESTART, ret, "hdb_create");
    ret = hdb_set_master_keyfile(context,
				 mydb, local_context->config.stash_file);
    if(ret)
        krb5_err(context, IPROPD_RESTART, ret, "hdb_set_master_keyfile");

    ret = mydb->hdb_open(context, mydb, O_RDWR | O_CREAT, 0600);
    if (ret)
        krb5_err(context, IPROPD_RESTART, ret, "db->open");

    (void) mydb->hdb_set_sync(context, mydb, 0);

    sp = NULL;
    krb5_data_zero(&data);
    do {
        krb5_data fake_data;
        HDB_entry upstream, existing, resolved;
        int drop = 0;

	ret = krb5_read_priv_message(context, auth_context, &fd, &data);
	if (ret)
            krb5_err(context, IPROPD_RESTART_SLOW, ret,
                     "krb5_read_priv_message");

	sp = krb5_storage_from_data(&data);
	if (sp == NULL)
	    krb5_errx(context, IPROPD_RESTART, "krb5_storage_from_data");
	krb5_ret_uint32(sp, &opcode);
	if (opcode != ONE_PRINC)
            break;

        krb5_storage_free(sp);

        fake_data.data   = (char *)data.data + 4;
        fake_data.length = data.length - 4;

        memset(&upstream, 0, sizeof(upstream));
        resolved = existing = upstream;

        /*
         * We could really use an hdb_store() that takes an encoded entry
         * and writes it w/o further ado instead of decoding then encoding.
         * But even then it'd be nice to have an encoding validator (that
         * doesn't decode) so that we can refuse to write broken entries.
         */
        ret = hdb_value2entry(context, &fake_data, &upstream);
        if (ret)
            krb5_err(context, IPROPD_RESTART, ret, "hdb_value2entry");

        update_last_time_seen(&upstream, &last_time_seen);

        ret = hdb_fetch_kvno(context, mydb, upstream.principal,
                             HDB_F_DECRYPT |
                             HDB_F_GET_ANY |
                             HDB_F_ADMIN_DATA, 0, 0,
                             0, &existing);
        if (ret != 0 && ret != HDB_ERR_NOENTRY)
            krb5_err(context, IPROPD_RESTART_SLOW, ret, "Could not read HDB");
        ret = resolve_conflict(context, local_context, kadm_create, master,
                               &upstream,
                               ret == 0 ? &existing : NULL,
                               &drop, &resolved);
        /* TODO: Add verbose logging here */
        if (!drop) {
            if (ret == 0)
                ret = mydb->hdb_store(context, mydb, HDB_F_REPLACE, &resolved);
            if (ret)
                krb5_err(context, IPROPD_RESTART_SLOW, ret, "hdb_store");
        }

        hdb_free_entry(context, mydb, &resolved);
        hdb_free_entry(context, mydb, &existing);
        hdb_free_entry(context, mydb, &upstream);
        krb5_data_free(&data);
    } while (opcode == ONE_PRINC);

    if (opcode != NOW_YOU_HAVE)
        krb5_errx(context, IPROPD_FATAL, "strange opcode %d", opcode);

    ret = krb5_ret_uint32(sp, &vno);
    if (ret)
        krb5_errx(context, IPROPD_RESTART_SLOW,
                  "merge_everything: no version number for NOW_YOU_HAVE");

    ret = krb5_ret_uint32(sp, &tstamp);
    if (ret == HEIM_ERR_EOF || tstamp == 0)
        tstamp = last_time_seen;
    else if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret,
                 "merge_everything: no timestamp for NOW_YOU_HAVE");
    server_context->log_context.version = vno;
    server_context->log_context.last_time = tstamp;
    krb5_storage_free(sp);
    krb5_data_free(&data);

    hook(server_context->context, master, "NOW_YOU_HAVE",
         "%"PRIu32" %"PRIu32, vno, tstamp);

    ret = mydb->hdb_set_sync(context, mydb, !async_hdb);
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret, "failed to sync the received HDB");

    reinit_log(server_context->context, server_context, vno, tstamp);
    (void) kadm5_log_nop(local_context, kadm_nop_plain);

    ret = mydb->hdb_close(context, mydb);
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret, "db->close");
    ret = mydb->hdb_destroy(context, mydb);
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret, "db->destroy");
    (void) kadm5_log_unlock(local_context);
    return 0;
}

/* This function re-initializes a local HDB using an upstream full prop */
static krb5_error_code
receive_everything(krb5_context context, const char *master, int fd,
		   kadm5_server_context *server_context,
		   krb5_auth_context auth_context)
{
    int ret;
    krb5_data data;
    uint32_t vno = 0;
    uint32_t tstamp = 0;
    uint32_t opcode;
    uint32_t last_time_seen = 0; /* In case the upstream is older and doesn't
                                  * tell us its last_time */
    krb5_storage *sp;

    char *dbname;
    HDB *mydb;

    krb5_warnx(context, "receive complete database");
    hook(server_context->context, master, "TELL_YOU_EVERYTHING", "replace HDB");

    ret = kadm5_log_exclusivelock(server_context);
    if (ret)
        krb5_err(context, IPROPD_RESTART, ret,
                 "Failed to lock iprop log for writes");
    if (server_context->db->hdb_method_name) {
        ret = asprintf(&dbname, "%.*s:%s-NEW",
                       (int) strlen(server_context->db->hdb_method_name) - 1,
                       server_context->db->hdb_method_name,
                       server_context->db->hdb_name);
    } else {
        ret = asprintf(&dbname, "%s-NEW", server_context->db->hdb_name);
    }
    if (ret == -1)
        krb5_err(context, IPROPD_RESTART, ENOMEM, "asprintf");
    ret = hdb_create(context, &mydb, dbname);
    if(ret)
        krb5_err(context, IPROPD_RESTART, ret, "hdb_create");
    free(dbname);

    ret = hdb_set_master_keyfile(context,
				 mydb, server_context->config.stash_file);
    if(ret)
        krb5_err(context, IPROPD_RESTART, ret, "hdb_set_master_keyfile");

    ret = mydb->hdb_open(context, mydb, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (ret)
        krb5_err(context, IPROPD_RESTART, ret, "db->open");

    (void) mydb->hdb_set_sync(context, mydb, 0);

    sp = NULL;
    krb5_data_zero(&data);
    do {
	ret = krb5_read_priv_message(context, auth_context, &fd, &data);

	if (ret) {
	    krb5_warn(context, ret, "krb5_read_priv_message");
	    goto cleanup;
	}

	sp = krb5_storage_from_data(&data);
	if (sp == NULL)
	    krb5_errx(context, IPROPD_RESTART, "krb5_storage_from_data");
	krb5_ret_uint32(sp, &opcode);
	if (opcode == ONE_PRINC) {
	    krb5_data fake_data;
	    hdb_entry entry;

	    krb5_storage_free(sp);

	    fake_data.data   = (char *)data.data + 4;
	    fake_data.length = data.length - 4;

	    memset(&entry, 0, sizeof(entry));

            /*
             * We could really use an hdb_store() that takes an encoded entry
             * and writes it w/o further ado instead of decoding then encoding.
             * But even then it'd be nice to have an encoding validator (that
             * doesn't decode) so that we can refuse to write broken entries.
             */
	    ret = hdb_value2entry(context, &fake_data, &entry);
	    if (ret)
		krb5_err(context, IPROPD_RESTART, ret, "hdb_value2entry");

            update_last_time_seen(&entry, &last_time_seen);

            ret = mydb->hdb_store(context, mydb, 0, &entry);
	    if (ret)
		krb5_err(context, IPROPD_RESTART_SLOW, ret, "hdb_store");

	    hdb_free_entry(context, mydb, &entry);
	    krb5_data_free(&data);
	} else if (opcode == NOW_YOU_HAVE)
	    ;
	else
	    krb5_errx(context, 1, "strange opcode %d", opcode);
    } while (opcode == ONE_PRINC);

    if (opcode != NOW_YOU_HAVE)
        krb5_errx(context, IPROPD_FATAL,
                  "receive_everything: strange %d", opcode);

    ret = krb5_ret_uint32(sp, &vno);
    if (ret)
        krb5_errx(context, IPROPD_RESTART_SLOW,
                  "receive_everything: no version number for NOW_YOU_HAVE");
    ret = krb5_ret_uint32(sp, &tstamp);
    if (ret == HEIM_ERR_EOF || tstamp == 0)
        tstamp = last_time_seen;
    else if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret,
                 "receive_everything: no timestamp for NOW_YOU_HAVE");
    server_context->log_context.version = vno;
    server_context->log_context.last_time = tstamp;
    krb5_storage_free(sp);
    hook(server_context->context, master, "NOW_YOU_HAVE",
         "%"PRIu32" %"PRIu32, vno, tstamp);

    ret = mydb->hdb_set_sync(context, mydb, !async_hdb);
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret, "failed to sync the received HDB");

    reinit_log(context, server_context, vno, tstamp);

    ret = mydb->hdb_close(context, mydb);
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret, "db->close");

    ret = mydb->hdb_rename(context, mydb, server_context->db->hdb_name);
    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret, "db->rename");


    return 0;

 cleanup:
    krb5_data_free(&data);

    if (ret)
        krb5_err(context, IPROPD_RESTART_SLOW, ret, "db->close");

    ret = mydb->hdb_destroy(context, mydb);
    if (ret)
        krb5_err(context, IPROPD_RESTART, ret, "db->destroy");

    krb5_warnx(context, "receive complete database, version %ld", (long)vno);
    return ret;
}

static void
slave_status(krb5_context context,
	     const char *file,
	     const char *status, ...)
     __attribute__ ((__format__ (__printf__, 3, 4)));


static void
slave_status(krb5_context context,
	     const char *file,
	     const char *fmt, ...)
{
    char *status;
    char *fmt2;
    va_list args;
    int len;
    
    if (asprintf(&fmt2, "%s\n", fmt) == -1 || fmt2 == NULL) {
        (void) unlink(file);
        return;
    }
    va_start(args, fmt);
    len = vasprintf(&status, fmt2, args);
    free(fmt2);
    va_end(args);
    if (len < 0 || status == NULL) {
	(void) unlink(file);
	return;
    }
    if (verbose)
        krb5_warnx(context, "writing slave status to file %s: %s", file,
                   status);
    rk_dumpdata(file, status, len);
    krb5_warnx(context, "slave status change: %s", status);
    free(status);
}

static void
is_up_to_date(krb5_context context, const char *file,
	      kadm5_server_context *server_context)
{
    krb5_error_code ret;
    char buf[80];
    ret = krb5_format_time(context, time(NULL), buf, sizeof(buf), 1);
    if (ret) {
	unlink(file);
	return;
    }
    slave_status(context, file, "up-to-date with version: %lu at %s",
		 (unsigned long)server_context->log_context.version, buf);
}

static int self_pipe[2] = { -1, -1 };
static void
sighandler(int sig)
{
    unsigned char c = sig;

    while (write(self_pipe[1], &c, 1) == -1 && errno == EINTR)
        ;
}

static char *database;
static char *status_file;
static char *config_file;
static int version_flag;
static int help_flag;
static char *port_str;
static int detach_from_console;
static int daemon_child = -1;
static int restarter_flag = 1;

static struct getargs args[] = {
    { "multi-master", 'M', arg_flag, &multi_master_flag,
        "enable multi-master", NULL},
    { "config-file", 'c', arg_string, &config_file, NULL, NULL },
    { "realm", 'r', arg_string, &realm, NULL, NULL },
    { "database", 'd', arg_string, &database, "database", "file"},
    { "no-keytab", 0, arg_flag, &no_keytab_flag,
      "use externally refreshed cache", NULL },
    { "ccache", 0, arg_string, &ccache_str,
      "client credentials", "CCACHE" },
    { "keytab", 'k', arg_string, &keytab_str,
      "client credentials keytab", "KEYTAB" },
    { "time-lost", 0, arg_string, &server_time_lost,
      "time before server is considered lost", "time" },
    { "status-file", 0, arg_string, &status_file,
      "file to write out status into", "file" },
    { "port", 0, arg_string, &port_str,
      "port ipropd-slave will connect to", "port"},
    { "detach", 0, arg_flag, &detach_from_console,
      "detach from console", NULL },
    { "daemon-child", 0, arg_integer, &daemon_child,
      "private argument, do not use", NULL },
    { "pidfile-basename", 0, arg_string, &pidfile_basename,
      "basename of pidfile; private argument for testing", "NAME" },
    { "async-hdb", 'a', arg_flag, &async_hdb, NULL, NULL },
    { "hostname", 0, arg_string, &local_hostname_str,
      "hostname of slave (if not same as hostname)", "hostname" },
    { "restarter", 0, arg_negative_flag, &restarter_flag, NULL, NULL },
    { "verbose", 0, arg_counter, &verbose, NULL, NULL },
    { "version", 0, arg_flag, &version_flag, NULL, NULL },
    { "help", 0, arg_flag, &help_flag, NULL, NULL }
};

static int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(int status)
{
    arg_printusage(args, num_args, NULL, "master");
    exit(status);
}

int
main(int argc, char **argv)
{
    krb5_error_code ret, ret2;
    krb5_context context;
    krb5_auth_context auth_context;
    struct sigaction sa;
    void *kadm_handle = NULL;
    kadm5_server_context *server_context;
    kadm5_server_context *local_context = NULL;
    kadm5_config_params conf;
    int master_fd;
    krb5_ccache ccache = NULL;
    krb5_principal server;
    char **files;
    int optidx = 0;
    time_t reconnect_min;
    time_t backoff;
    time_t reconnect_max;
    time_t reconnect;
    time_t before = 0;
    int restarter_fd = -1;

    setprogname(argv[0]);

    if (getarg(args, num_args, argc, argv, &optidx))
	usage(1);

    if (help_flag)
	usage(0);

    if (version_flag) {
	print_version(NULL);
	exit(0);
    }

    if (detach_from_console && daemon_child == -1)
        daemon_child = roken_detach_prep(argc, argv, "--daemon-child");
    rk_pidfile(pidfile_basename);

    ret = krb5_init_context(&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    setup_signal();
    /* XXX Move this stuff into setup_signal(), no? */
    if (pipe(self_pipe) == -1)
        krb5_err(context, 1, errno, "Could not set up self-pipe");
    (void) fcntl(self_pipe[0], F_SETFL,
                 (int)fcntl(self_pipe[0], F_GETFL) | O_NONBLOCK);
    (void) fcntl(self_pipe[1], F_SETFL,
                 (int)fcntl(self_pipe[1], F_GETFL) | O_NONBLOCK);
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    if (config_file == NULL) {
	if (asprintf(&config_file, "%s/kdc.conf", hdb_db_dir(context)) == -1
	    || config_file == NULL)
	    errx(1, "out of memory");
    }

    ret = krb5_prepend_config_files_default(config_file, &files);
    if (ret)
	krb5_err(context, 1, ret, "getting configuration files");

    ret = krb5_set_config_files(context, files);
    krb5_free_config_files(files);
    if (ret)
	krb5_err(context, 1, ret, "reading configuration files");

    argc -= optidx;
    argv += optidx;

    if (argc != 1 && argc != 2)
	usage(1);

    master_name = connect_to = argv[0];
    if (argc == 2)
        connect_to = argv[1];

    if (status_file == NULL) {
	if (asprintf(&status_file,  "%s/ipropd-slave-status", hdb_db_dir(context)) < 0 || status_file == NULL)
	    krb5_errx(context, 1, "can't allocate status file buffer"); 
    }

    krb5_openlog(context, "ipropd-slave", &log_facility);
    krb5_set_warn_dest(context, log_facility);

    slave_status(context, status_file, "bootstrapping");

    ret = krb5_kt_register(context, &hdb_get_kt_ops);
    if(ret)
	krb5_err(context, 1, ret, "krb5_kt_register");

    time_before_lost = parse_time (server_time_lost,  "s");
    if (time_before_lost < 0)
	krb5_errx (context, 1, "couldn't parse time: %s", server_time_lost);

    slave_status(context, status_file, "getting credentials from keytab/database");

    /* Has side-effect of setting `local_hostname_str' if it's not set yet */
    get_creds(context, &ccache, master_name);
    local_KDC_name = local_hostname_str;

    memset(&conf, 0, sizeof(conf));
    if(realm) {
	conf.mask |= KADM5_CONFIG_REALM;
	conf.realm = realm;
    }
    if (database) {
	conf.mask |= KADM5_CONFIG_DBNAME;
	conf.dbname = database;
    }
    if (local_hostname_str) {
	conf.mask |= KADM5_CONFIG_LOCAL_KDC_NAME;
	conf.local_kdc_name = local_hostname_str;
    } else if (multi_master_flag) {
        krb5_errx(context, 1, "Could not determine local hostname");
    }
    ret = kadm5_init_with_password_ctx (context,
					KADM5_ADMIN_SERVICE,
					NULL,
					KADM5_ADMIN_SERVICE,
					&conf, 0, 0,
					&kadm_handle);
    if (ret)
	krb5_err (context, 1, ret, "kadm5_init_with_password_ctx");
    server_context = (kadm5_server_context *)kadm_handle;
    kadm_handle = NULL;

    if (multi_master_flag) {
        const char *log_file = server_context->log_context.log_file;
        const char *stem = strrchr(log_file, '.');
        size_t log_file_len = strlen(log_file);
        char *s = NULL;

        /*
         * For multi-master, the log for the master we're following has to have
         * that master's name in the file name.
         *
         * The log in the local_context remains the one we use for local
         * operations.
         */
        if (!stem || strcmp(stem, ".log") != 0)
            stem = log_file + log_file_len;
        ret = asprintf(&s, "%.*s-%s%s", (int)(stem - log_file), log_file,
                       master_name, stem[0] == '.' ? stem : "");
        if (ret == -1 || s == NULL)
            errx(1, "Out of memory");

        free(server_context->log_context.log_file);
        server_context->log_context.log_file = s;
    }

    slave_status(context, status_file, "opening HDB");

    ret = server_context->db->hdb_open(context,
                                       server_context->db,
                                       O_RDWR | O_CREAT, 0600);
    if (ret)
	krb5_err (context, 1, ret, "db->open");

    slave_status(context, status_file, "creating log file");
    ret = kadm5_log_init(server_context);
    if (ret)
	krb5_err(context, 1, ret, "kadm5_log_init");
    (void) kadm5_log_sharedlock(server_context);
    if (verbose)
        krb5_warnx(context, "downgraded iprop log lock to shared");

    ret = server_context->db->hdb_close(context, server_context->db);
    if (ret)
	krb5_err(context, 1, ret, "db->close");

    if (multi_master_flag) {
        ret = kadm5_init_with_password_ctx(context,
                                           KADM5_ADMIN_SERVICE,
                                           NULL,
                                           KADM5_ADMIN_SERVICE,
                                           &conf, 0, 0,
                                           &kadm_handle);
        if (ret)
            krb5_err(context, 1, ret, "kadm5_init_with_password_ctx");
        local_context = kadm_handle;
        kadm_handle = NULL;
        ret = local_context->db->hdb_open(context, local_context->db,
                                          O_RDWR | O_CREAT, 0600);
        if (ret)
            krb5_err (context, 1, ret, "db->open");

        ret = kadm5_log_init(local_context);
        if (ret)
            krb5_err(context, 1, ret, "kadm5_log_init");
        (void) kadm5_log_unlock(local_context);
        if (verbose)
            krb5_warnx(context, "dropped lock on local iprop log");

        ret = local_context->db->hdb_close(context, local_context->db);
        if (ret)
            krb5_err(context, 1, ret, "db->close");
    }

    ret = krb5_sname_to_principal (context, master_name, IPROP_NAME,
				   KRB5_NT_SRV_HST, &server);
    if (ret)
	krb5_err (context, 1, ret, "krb5_sname_to_principal");

    auth_context = NULL;
    master_fd = -1;

    krb5_appdefault_time(context, config_name, NULL, "reconnect-min",
			 10, &reconnect_min);
    krb5_appdefault_time(context, config_name, NULL, "reconnect-max",
			 300, &reconnect_max);
    krb5_appdefault_time(context, config_name, NULL, "reconnect-backoff",
			 10, &backoff);
    reconnect = reconnect_min;

    slave_status(context, status_file, "ipropd-slave started");

    roken_detach_finish(NULL, daemon_child);
    if (restarter_flag)
        restarter_fd = restarter(context, NULL);

    while (!exit_flag) {
        struct timeval to;
	time_t now, elapsed;
        fd_set readset;
	int connected = FALSE;

#ifndef NO_LIMIT_FD_SETSIZE
        if (restarter_fd >= FD_SETSIZE)
            krb5_errx(context, IPROPD_RESTART, "fd too large");
#endif

        FD_ZERO(&readset);
        if (restarter_fd > -1)
            FD_SET(restarter_fd, &readset);
        if (self_pipe[0] > -1)
            FD_SET(self_pipe[0], &readset);

	now = time(NULL);
	elapsed = now - before;

	if (elapsed < reconnect) {
	    time_t left = reconnect - elapsed;
	    krb5_warnx(context, "sleeping %d seconds before "
		       "retrying to connect", (int)left);
            to.tv_sec = left;
            to.tv_usec = 0;
            if (restarter_fd > -1 &&
                select(restarter_fd + 1, &readset, NULL, NULL, &to) == 1) {
                exit_flag = SIGTERM;
                continue;
            }
	}
	before = now;

	slave_status(context, status_file, "connecting to master: %s\n",
                     master_name);

	master_fd = connect_to_master (context, connect_to, port_str);
	if (master_fd < 0)
	    goto retry;

	reconnect = reconnect_min;

	if (auth_context) {
	    krb5_auth_con_free(context, auth_context);
	    auth_context = NULL;
	    get_creds(context, &ccache, master_name);
	}
        if (verbose)
            krb5_warnx(context, "authenticating to master");
	ret = krb5_sendauth (context, &auth_context, &master_fd,
			     IPROP_VERSION, NULL, server,
			     AP_OPTS_MUTUAL_REQUIRED, NULL, NULL,
			     ccache, NULL, NULL, NULL);
	if (ret) {
	    krb5_warn (context, ret, "krb5_sendauth");
	    goto retry;
	}

	krb5_warnx(context, "ipropd-slave started at version: %ld",
		   (long)server_context->log_context.version);

        ret = kadm5_log_get_version(server_context,
                                    &server_context->log_context.version,
                                    &server_context->log_context.last_time);
        if (ret)
            krb5_errx(context, IPROPD_RESTART,
                      "could not read upstream version from log file");
	ret = ihave(context, master_name, auth_context, master_fd,
		    server_context->log_context.version,
                    server_context->log_context.last_time);
	if (ret)
	    goto retry;

	connected = TRUE;

        if (verbose)
            krb5_warnx(context, "connected to master");

	slave_status(context, status_file, "connected to master, waiting instructions");

	while (connected && !exit_flag) {
	    krb5_data out;
	    krb5_storage *sp;
	    uint32_t tmp;
            int max_fd, nfds;

#ifndef NO_LIMIT_FD_SETSIZE
	    if (master_fd >= FD_SETSIZE)
                krb5_errx(context, IPROPD_RESTART, "fd too large");
            if (restarter_fd >= FD_SETSIZE)
                krb5_errx(context, IPROPD_RESTART, "fd too large");
            if (self_pipe[0] >= FD_SETSIZE)
                krb5_errx(context, IPROPD_RESTART, "fd too large");
            max_fd = max(max(restarter_fd, master_fd), self_pipe[0]);
#endif

	    FD_ZERO(&readset);
	    FD_SET(master_fd, &readset);
	    FD_SET(self_pipe[0], &readset);
            if (restarter_fd != -1)
                FD_SET(restarter_fd, &readset);

	    to.tv_sec = time_before_lost;
	    to.tv_usec = 0;

	    nfds = select (max_fd + 1,
			  &readset, NULL, NULL, &to);
	    if (nfds < 0) {
		if (errno == EINTR)
		    continue;
		else
		    krb5_err (context, 1, errno, "select");
	    }
	    if (nfds == 0) {
		krb5_warnx(context, "server didn't send a message "
                           "in %d seconds", time_before_lost);
		connected = FALSE;
		continue;
	    }

            if (restarter_fd > -1 && FD_ISSET(restarter_fd, &readset)) {
                if (verbose)
                    krb5_warnx(context, "slave restarter exited");
                exit_flag = SIGTERM;
            }

            if (FD_ISSET(self_pipe[0], &readset)) {
                unsigned char sig;
                ssize_t bytes;

                do {
                    bytes = read(self_pipe[0], &sig, 1);
                    if (bytes == 1) {
                        switch (sig) {
                            case SIGUSR1:
                                verbose++;
                                break;
                            case SIGUSR2:
                                verbose--;
                                break;
                            case SIGHUP:
                                rk_closesocket(master_fd);
                                master_fd = rk_INVALID_SOCKET;
                                connected = false;
                                break;
                        }
                    }
                } while ((bytes == -1 && errno == EINTR) || bytes == 1);
            }

            if (!connected)
                continue;

            if (!FD_ISSET(master_fd, &readset))
                continue;

            if (verbose)
                krb5_warnx(context, "message from master");

	    ret = krb5_read_priv_message(context, auth_context, &master_fd, &out);
	    if (ret) {
		krb5_warn(context, ret, "krb5_read_priv_message");
		connected = FALSE;
		continue;
	    }

	    sp = krb5_storage_from_mem (out.data, out.length);
            if (sp == NULL)
                krb5_err(context, IPROPD_RESTART, errno, "krb5_storage_from_mem");
	    ret = krb5_ret_uint32(sp, &tmp);
            if (ret == HEIM_ERR_EOF) {
                krb5_warn(context, ret, "master sent zero-length message");
                connected = FALSE;
                continue;
            }
            if (ret != 0) {
                krb5_warn(context, ret, "couldn't read master's message");
                connected = FALSE;
                continue;
            }

            /*
             * It's unclear why we open th HDB and call kadm5_log_init() here.
             *
             * We don't need it to process the log entries we receive in the
             * FOR_YOU case: we already call kadm5_log_recover() in receive() /
             * receive_loop().  Maybe it's just just in case, though at the
             * cost of synchronization with ipropd-master if we're running one
             * for hierarchical iprop.
             */
	    ret = server_context->db->hdb_open(context,
					       server_context->db,
					       O_RDWR | O_CREAT, 0600);
	    if (ret)
		krb5_err (context, 1, ret, "db->open while handling a "
			  "message from the master");
            ret = kadm5_log_init(server_context);
            if (ret) {
                krb5_err(context, IPROPD_RESTART, ret, "kadm5_log_init while "
                         "handling a message from the master");
            }
            (void) kadm5_log_sharedlock(server_context);
            if (verbose)
                krb5_warnx(context, "downgraded iprop log lock to shared");

	    ret = server_context->db->hdb_close (context, server_context->db);
	    if (ret)
		krb5_err (context, 1, ret, "db->close while handling a "
			  "message from the master");

	    switch (tmp) {
	    case FOR_YOU :
                if (verbose)
                    krb5_warnx(context, "master sent us diffs");
                ret2 = receive(context, master_name, sp, server_context,
                               local_context);
                if (ret2)
                    krb5_warn(context, ret2,
                              "receive from ipropd-master had errors");
		ret = ihave(context, master_name, auth_context, master_fd,
			    server_context->log_context.version,
                            server_context->log_context.last_time);
		if (ret || ret2)
		    connected = FALSE;

                /*
                 * If it returns an error, receive() may nonetheless
                 * have committed some entries successfully, so we must
                 * update the slave_status even if there were errors.
                 */
                is_up_to_date(context, status_file, server_context);
		break;
	    case TELL_YOU_EVERYTHING :
                if (verbose)
                    krb5_warnx(context, "master sent us a full dump");
                if (multi_master_flag) {
                    ret = merge_everything(context, master_name, master_fd,
                                           server_context, local_context,
                                           auth_context);
                    if (ret == 0)
                        /*
                         * Make sure there's at least one entry in the log now
                         * that we have a complete DB.
                         *
                         * XXX Do we need to re-initialize our log after
                         *     receiving a complete HDB from an upstream??
                         */
                        ret = kadm5_log_nop(local_context, kadm_nop_plain);
                } else {
                    ret = receive_everything(context, master_name, master_fd,
                                             server_context, auth_context);
                }
                (void) kadm5_log_sharedlock(server_context);
                if (ret == 0) {
                    ret = ihave(context, master_name, auth_context, master_fd,
                                server_context->log_context.version,
                                server_context->log_context.last_time);
                }
                if (ret)
		    connected = FALSE;
                else
                    is_up_to_date(context, status_file, server_context);
                if (verbose)
                    krb5_warnx(context, "downgraded iprop log lock to shared");

                /* For hierarchical and multi-master iprop */
                kadm5_log_signal_master(local_context ? local_context : server_context);
                if (verbose)
                    krb5_warnx(context, "signaled master for hierarchical iprop");
		break;
	    case ARE_YOU_THERE :
                if (verbose)
                    krb5_warnx(context, "master sent us a ping");
		is_up_to_date(context, status_file, server_context);
                /*
                 * We used to send an I_HAVE here.  But the master may send
                 * ARE_YOU_THERE messages in response to local, possibly-
                 * transient errors, and if that happens and we respond with an
                 * I_HAVE then we'll loop hard if the error was not transient.
                 *
                 * So we don't ihave() here.
                 */
		send_im_here(context, master_name, master_fd, auth_context);
		break;
	    case YOU_HAVE_LAST_VERSION:
                hook(server_context->context, master_name,
                     "YOU_HAVE_LAST_VERSION", "");
                if (verbose)
                    krb5_warnx(context, "master tells us we are up to date");
		is_up_to_date(context, status_file, server_context);
		break;
	    case NOW_YOU_HAVE :
	    case I_HAVE :
	    case ONE_PRINC :
	    case I_AM_HERE :
	    default :
		krb5_warnx (context, "Ignoring command %d", tmp);
		break;
	    }
	    krb5_storage_free (sp);
	    krb5_data_free (&out);

	}

	slave_status(context, status_file, "disconnected from master");
    retry:
	if (connected == FALSE)
	    krb5_warnx (context, "disconnected for server");

	if (exit_flag)
	    krb5_warnx (context, "got an exit signal");

	if (master_fd >= 0)
	    close(master_fd);

	reconnect += backoff;
	if (reconnect > reconnect_max) {
	    slave_status(context, status_file, "disconnected from master for a long time");
	    reconnect = reconnect_max;
	}
    }

    if (status_file) {
        /* XXX It'd be better to leave it saying we're not here */
	unlink(status_file);
    }

    if (0);
#ifndef NO_SIGXCPU
    else if(exit_flag == SIGXCPU)
	krb5_warnx(context, "%s CPU time limit exceeded", getprogname());
#endif
    else if(exit_flag == SIGINT || exit_flag == SIGTERM)
	krb5_warnx(context, "%s terminated", getprogname());
    else
	krb5_warnx(context, "%s unexpected exit reason: %ld",
		       getprogname(), (long)exit_flag);

    if (local_context) {
        if (local_context->db)
            local_context->db->hdb_destroy(context, local_context->db);
        local_context->db = NULL;
        kadm5_destroy(local_context);
    }
    if (server_context)
        kadm5_destroy(server_context);
    if (ccache)
        krb5_cc_destroy(context, ccache);
    if (server)
        krb5_free_principal(context, server);
    if (auth_context)
        krb5_auth_con_free(context, auth_context);
    if (context)
        krb5_free_context(context);

    return 0;
}
