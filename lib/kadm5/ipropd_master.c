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
#include <rtbl.h>

static krb5_log_facility *log_facility;

static int verbose;

const char *slave_stats_file;
const char *slave_time_missing = "2 min";
const char *slave_time_gone = "5 min";

static int time_before_missing;
static int time_before_gone;

static int protocol_version = IPROP_PROTOCOL_VERSION;

const char *master_hostname;

static krb5_socket_t
make_signal_socket (krb5_context context)
{
#ifndef NO_UNIX_SOCKETS
    struct sockaddr_un addr;
    const char *fn;
    krb5_socket_t fd;

    fn = kadm5_log_signal_socket(context);

    fd = socket (AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
	krb5_err (context, 1, errno, "socket AF_UNIX");
    memset (&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy (addr.sun_path, fn, sizeof(addr.sun_path));
    unlink (addr.sun_path);
    if (bind (fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	krb5_err (context, 1, errno, "bind %s", addr.sun_path);
    return fd;
#else
    struct addrinfo *ai = NULL;
    krb5_socket_t fd;

    kadm5_log_signal_socket_info(context, 1, &ai);

    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (rk_IS_BAD_SOCKET(fd))
	krb5_err (context, 1, rk_SOCK_ERRNO, "socket AF=%d", ai->ai_family);

    if (rk_IS_SOCKET_ERROR( bind (fd, ai->ai_addr, ai->ai_addrlen) ))
	krb5_err (context, 1, rk_SOCK_ERRNO, "bind");
    return fd;
#endif
}

static krb5_socket_t
make_listen_socket (krb5_context context, const char *port_str)
{
    krb5_socket_t fd;
    int one = 1;
    struct sockaddr_in addr;

    fd = socket (AF_INET, SOCK_STREAM, 0);
    if (rk_IS_BAD_SOCKET(fd))
	krb5_err (context, 1, rk_SOCK_ERRNO, "socket AF_INET");
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));
    memset (&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    if (port_str) {
	addr.sin_port = krb5_getportbyname (context,
					      port_str, "tcp",
					      0);
	if (addr.sin_port == 0) {
	    char *ptr;
	    long port;

	    port = strtol (port_str, &ptr, 10);
	    if (port == 0 && ptr == port_str)
		krb5_errx (context, 1, "bad port `%s'", port_str);
	    addr.sin_port = htons(port);
	}
    } else {
	addr.sin_port = krb5_getportbyname (context, IPROP_SERVICE,
					    "tcp", IPROP_PORT);
    }
    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	krb5_err (context, 1, errno, "bind");
    if (listen(fd, SOMAXCONN) < 0)
	krb5_err (context, 1, errno, "listen");
    return fd;
}

struct read_buffer {
    char        *buf;
    size_t      bufsz;
    size_t      bytesread;
};

/*
 * A lot like krb5_read_message, but restartable.
 */
static krb5_error_code
read_msg(krb5_context context, int fd, struct read_buffer *b)
{
    uint32_t len;
    ssize_t bytes;

    if (b->buf == NULL &&
        (b->buf = malloc(b->bufsz = 8192)) == NULL)
        krb5_err(context, IPROPD_RESTART_SLOW, errno, "malloc");

    if (b->bytesread > sizeof(len) &&
        b->bytesread + sizeof(len)) {
        /* Last msg was read and handled; reset buffer and read new msg */
        b->bytesread = 0;
    }

    if (b->bytesread < sizeof(len)) {
        bytes = net_read(fd, b->buf + b->bytesread, sizeof(len) - b->bytesread);
        if (bytes < 0)
            return errno;
        b->bytesread += bytes;
        if (b->bytesread < sizeof(len))
            return -1;
    }

    len = (b->buf[0] << 24) | (b->buf[1] << 16) | (b->buf[2] << 8) | b->buf[3];
    if (len + sizeof(len) > b->bufsz) {
        b->bufsz = len + sizeof(len) + 4096;
        if ((b->buf = realloc(b->buf, b->bufsz)) == NULL)
            krb5_err(context, IPROPD_RESTART_SLOW, errno, "realloc");
    }

    if (b->bytesread - sizeof(len) < len) {
        bytes = net_read(fd, b->buf + b->bytesread,
                       len - (b->bytesread - sizeof(len)));
        if (bytes < 0)
            return errno;
        b->bytesread += bytes;
        if (b->bytesread < sizeof(len))
            return -1;
    }

    return 0;
}

static krb5_error_code
read_priv(krb5_context context, krb5_auth_context ac, int fd,
          struct read_buffer *b, krb5_data *d)
{
    krb5_error_code ret;
    krb5_data p;

    d->data = NULL;
    d->length = 0;
    ret = read_msg(context, fd, b);
    if (ret)
        return ret;
    if (b->bytesread < sizeof(uint32_t))
        return EINVAL; /* Shouldn't happen */
    p.data = b->buf + sizeof(uint32_t);
    p.length = b->bytesread - sizeof(uint32_t);
    return krb5_rd_priv(context, ac, &p, d, NULL);
}

struct write_buffer {
    krb5_data   d;
    size_t      byteswritten;
};

static krb5_error_code
write_msg(krb5_context context, int fd, struct write_buffer *b)
{
    ssize_t bytes;

    if (b->byteswritten == b->d.length)
        return 0;

    bytes = net_write(fd, b->d.data, b->d.length - b->byteswritten);
    if (bytes < 0)
        return errno;

    b->byteswritten += bytes;

    if (b->byteswritten != b->d.length)
        return EAGAIN;
    return 0;
}

static krb5_error_code
write_priv(krb5_context context, krb5_auth_context ac, int fd,
           struct write_buffer *b, krb5_data *d)
{
    krb5_error_code ret;

    krb5_data_free(&b->d);
    b->byteswritten = 0;

    ret = krb5_mk_priv(context, ac, d, &b->d, NULL);
    if (ret)
        return ret;
    return write_msg(context, fd, b);
}

/*
 * Async/interleaved operation state.
 */
typedef enum iprop_state {
    IPROP_SLAVE_STATE_IDLE = 0,
    IPROP_SLAVE_STATE_COMPLETE = 1, /* sending complete */
    /*
     * Slaves in COMPLETE blocking one that needs a new dump.  Whenever such a
     * slave switches to IDLE we will attempt to restart a slave in
     * NEEDS_DUMP_LOCK, if there are any such slaves.
     */
    IPROP_SLAVE_STATE_NEEDS_DUMP_LOCK = 3,
} iprop_state;

struct slave {
    krb5_socket_t fd;
    struct sockaddr_in addr;
    char *name;
    krb5_auth_context ac;
    uint32_t protocol_version;
    iprop_version version;
    time_t seen;
    unsigned long flags;
#define SLAVE_F_DEAD            0x1
#define SLAVE_F_AYT             0x2
#define SLAVE_F_SENT_COMPLETE   0x4
    struct slave *next;
    /* state machine for async/interleaved send_complete() */
    iprop_state state;
    krb5_storage *dump;
    iprop_version dump_vno;
    /*
     * XXX We need to use non-blocking sockets for the slaves, and we need to
     * buffer the last message in case of incomplete write.  The message and
     * offset into it that remains unsent needs to be recorded here.
     *
     * We need to do this for *all* messages we send to the slave, naturally.
     *
     * Ditto reading.
     *
     * Otherwise a blocked slave can keep us from servicing others.
     *
     * At this point, however, it would be best to switch to libknc.
     */
};

typedef struct slave slave;

static int
check_acl (krb5_context context, const char *name)
{
    const char *fn;
    FILE *fp;
    char buf[256];
    int ret = 1;
    char *slavefile = NULL;

    if (asprintf(&slavefile, "%s/slaves", hdb_db_dir(context)) == -1
	|| slavefile == NULL)
	errx(1, "out of memory");

    fn = krb5_config_get_string_default(context,
					NULL,
					slavefile,
					"kdc",
					"iprop-acl",
					NULL);

    fp = fopen (fn, "r");
    free(slavefile);
    if (fp == NULL)
	return 1;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
	buf[strcspn(buf, "\r\n")] = '\0';
	if (strcmp (buf, name) == 0) {
	    ret = 0;
	    break;
	}
    }
    fclose (fp);
    return ret;
}

static void
slave_seen(slave *s)
{
    s->flags &= ~SLAVE_F_AYT;
    s->seen = time(NULL);
}

static int
slave_missing_p (slave *s)
{
    if (time(NULL) > s->seen + time_before_missing)
	return 1;
    return 0;
}

static int
slave_gone_p (slave *s)
{
    if (s->flags & SLAVE_F_DEAD)
        return 1;
    if (time(NULL) > s->seen + time_before_gone)
	return 1;
    return 0;
}

static void
slave_dead(krb5_context context, slave *s)
{
    krb5_warnx(context, "slave %s dead", s->name);

    if (!rk_IS_BAD_SOCKET(s->fd)) {
	rk_closesocket (s->fd);
	s->fd = rk_INVALID_SOCKET;
    }
    s->flags |= SLAVE_F_DEAD;
    slave_seen(s);
}

static void
remove_slave (krb5_context context, slave *s, slave **root)
{
    slave **p;

    if (!rk_IS_BAD_SOCKET(s->fd))
	rk_closesocket (s->fd);
    if (s->name)
	free (s->name);
    if (s->ac)
	krb5_auth_con_free (context, s->ac);
    krb5_storage_free(s->dump);

    for (p = root; *p; p = &(*p)->next)
	if (*p == s) {
	    *p = s->next;
	    break;
	}
    free (s);
}

static void
add_slave (krb5_context context, krb5_keytab keytab, slave **root,
	   krb5_socket_t fd)
{
    krb5_principal server;
    krb5_error_code ret;
    slave *s;
    socklen_t addr_len;
    krb5_ticket *ticket = NULL;
    char hostname[128];

    s = calloc(1, sizeof(*s));
    if (s == NULL) {
	krb5_warnx (context, "add_slave: no memory");
	return;
    }
    s->name = NULL;
    s->ac = NULL;
    s->state = IPROP_SLAVE_STATE_IDLE;
    s->dump = NULL;

    addr_len = sizeof(s->addr);
    s->fd = accept (fd, (struct sockaddr *)&s->addr, &addr_len);
    if (rk_IS_BAD_SOCKET(s->fd)) {
	krb5_warn (context, rk_SOCK_ERRNO, "accept");
	goto error;
    }
    if (master_hostname)
	strlcpy(hostname, master_hostname, sizeof(hostname));
    else
	gethostname(hostname, sizeof(hostname));

    ret = krb5_sname_to_principal (context, hostname, IPROP_NAME,
				   KRB5_NT_SRV_HST, &server);
    if (ret) {
	krb5_warn (context, ret, "krb5_sname_to_principal");
	goto error;
    }

    ret = krb5_recvauth (context, &s->ac, &s->fd,
			 IPROP_VERSION, server, 0, keytab, &ticket);
    krb5_free_principal (context, server);
    if (ret) {
	krb5_warn (context, ret, "krb5_recvauth");
	goto error;
    }
    ret = krb5_unparse_name (context, ticket->client, &s->name);
    krb5_free_ticket (context, ticket);
    if (ret) {
	krb5_warn (context, ret, "krb5_unparse_name");
	goto error;
    }
    if (check_acl (context, s->name)) {
	krb5_warnx (context, "%s not in acl", s->name);
	goto error;
    }

    {
	slave *l = *root;

	while (l) {
	    if (strcmp(l->name, s->name) == 0)
		break;
	    l = l->next;
	}
	if (l) {
	    if (l->flags & SLAVE_F_DEAD) {
		remove_slave(context, l, root);
	    } else {
		krb5_warnx (context, "second connection from %s", s->name);
		goto error;
	    }
	}
    }

    krb5_warnx (context, "connection from %s", s->name);

    s->version.vno = 0;
    s->version.tstamp = 0;
    s->flags = 0;
    slave_seen(s);
    s->next = *root;
    *root = s;
    return;
error:
    remove_slave(context, s, root);
}

static int
version_in_range(iprop_version first, iprop_version last, iprop_version v)
{
    return (last.vno - first.vno) < (UINT32_MAX >> 1) &&
        (v.vno - first.vno) < (last.vno - first.vno);
}

static int
version_cmp(iprop_version left, iprop_version right)
{
    if (left.vno == right.vno) {
        if (left.tstamp == 0 || right.tstamp == 0)
            return 0;
        return left.tstamp - right.tstamp;
    }
    return left.vno - right.vno;
}

static int
version_eq(iprop_version left, iprop_version right)
{
    if (left.vno != right.vno)
        return 0;
    if (left.tstamp == 0 || right.tstamp == 0)
        return 1;
    return left.tstamp == right.tstamp;
}

static int
version_lt(iprop_version left, iprop_version right)
{
    return (left.vno < right.vno);
}

static int
version_le(iprop_version left, iprop_version right)
{
    return version_lt(left, right) || version_eq(left, right);
}

static int
version_gt(iprop_version left, iprop_version right)
{
    return (left.vno > right.vno);
}

static int
version_ge(iprop_version left, iprop_version right)
{
    return version_gt(left, right) || version_eq(left, right);
}

static int
dump_one (krb5_context context, HDB *db, hdb_entry_ex *entry, void *v)
{
    krb5_error_code ret;
    krb5_storage *dump = (krb5_storage *)v;
    krb5_storage *sp;
    krb5_data data;

    ret = hdb_entry2value (context, &entry->entry, &data);
    if (ret)
	return ret;
    ret = krb5_data_realloc (&data, data.length + 4);
    if (ret)
	goto done;
    memmove ((char *)data.data + 4, data.data, data.length - 4);
    sp = krb5_storage_from_data(&data);
    if (sp == NULL) {
	ret = ENOMEM;
	goto done;
    }
    ret = krb5_store_uint32(sp, ONE_PRINC);
    krb5_storage_free(sp);

    if (ret == 0)
        ret = krb5_store_data(dump, data);

done:

    /*
     * XXX Here we should re-enter the main event loop every N records or
     * seconds to make sure that we don't starve any slaves for attention.
     */

    krb5_data_free (&data);
    return ret;
}

static int
write_dump(krb5_context context, krb5_storage *dump,
	   const char *database, iprop_version current_version)
{
    krb5_error_code ret;
    krb5_storage *sp;
    HDB *db;
    krb5_data data;
    char buf[sizeof(uint32_t) * 3];

    /* we assume that the caller has obtained an exclusive lock */

    ret = krb5_storage_truncate(dump, 0);
    if (ret)
	return ret;

    if (krb5_storage_seek(dump, 0, SEEK_SET) != 0)
        return errno;

    /*
     * First we store zero as the HDB version, this will indicate to a
     * later reader that the dumpfile is invalid.  We later write the
     * correct version in the file after we have written all of the
     * messages.  A dump with a zero version will not be considered
     * to be valid.
     */

    ret = krb5_store_uint32(dump, 0);

    ret = hdb_create (context, &db, database);
    if (ret)
	krb5_err (context, IPROPD_RESTART, ret, "hdb_create: %s", database);
    ret = db->hdb_open (context, db, O_RDONLY, 0);
    if (ret)
	krb5_err (context, IPROPD_RESTART, ret, "db->open");

    if (verbose)
        krb5_warnx(context, "TELL_YOU_EVERYTHING %u, %u", current_version.vno, current_version.tstamp);
    assert(sizeof(buf) >= sizeof(uint32_t) * 3);
    switch (protocol_version) {
    case 0: sp = krb5_storage_from_mem(buf, sizeof(uint32_t));
    case IPROP_PROTOCOL_VERSION: sp = krb5_storage_from_mem(buf, sizeof(uint32_t) * 3);
    }
    if (sp == NULL)
	krb5_errx(context, IPROPD_RESTART, "krb5_storage_from_mem");
    ret = krb5_store_uint32(sp, TELL_YOU_EVERYTHING);
    if (ret == 0 && protocol_version > 0)
        ret = krb5_store_uint32(sp, current_version.vno);
    if (ret == 0 && protocol_version > 0)
        krb5_store_uint32(sp, current_version.tstamp);
    krb5_storage_free(sp);
    if (ret)
	krb5_err(context, IPROPD_RESTART, ret, "writing dump");

    data.data   = buf;
    data.length = sizeof(uint32_t) * 3;

    ret = krb5_store_data(dump, data);

    if (ret == 0) {
        ret = hdb_foreach (context, db, HDB_F_ADMIN_DATA, dump_one, dump);
        if (ret)
            krb5_warn(context, ret, "write_dump: hdb_foreach");
    }

    (*db->hdb_close)(context, db);
    (*db->hdb_destroy)(context, db);

    assert(sizeof(buf) >= sizeof(uint32_t) * 3);
    switch (protocol_version) {
    case 0: sp = krb5_storage_from_mem(buf, sizeof(uint32_t));
    case IPROP_PROTOCOL_VERSION: sp = krb5_storage_from_mem(buf, sizeof(uint32_t) * 3);
    }
    if (sp == NULL)
	krb5_errx(context, IPROPD_RESTART, "krb5_storage_from_mem");
    if (ret == 0)
        ret = krb5_store_uint32(sp, NOW_YOU_HAVE);
    if (ret == 0 && protocol_version > 0)
        krb5_store_uint32(sp, current_version.vno);
    if (ret == 0 && protocol_version > 0)
        krb5_store_uint32(sp, current_version.tstamp);
    krb5_storage_free (sp);

    data.length = sizeof(uint32_t) * 3;
    if (ret == 0)
        ret = krb5_store_data(dump, data);

    /*
     * We must ensure that the entire valid dump is written to disk
     * before we write the current version at the front thus making
     * it a valid dump file.  If we crash around here, this can be
     * important upon reboot.
     */

    if (ret == 0)
        ret = krb5_storage_fsync(dump);

    if (ret == 0 && krb5_storage_seek(dump, 0, SEEK_SET) == -1)
	ret = errno;

    /* Write current version at the front making the dump valid */

    if (ret == 0)
        ret = krb5_store_uint32(dump, current_version.vno);

    /*
     * We don't need to fsync(2) after the real version is written as
     * it is not a disaster if it doesn't make it to disk if we crash.
     * After all, we'll just create a new dumpfile.
     */

    if (ret == 0)
        krb5_warnx(context, "wrote new dumpfile (version %u)",
                   current_version.vno);
    else
        krb5_warn(context, ret, "failed to write new dumpfile (version %u)",
                  current_version.vno);

    return ret;
}

static int
get_dump_metadata(krb5_storage *dump, iprop_version *v)
{
    krb5_error_code ret;
    krb5_storage *sp;
    krb5_data data;
    uint32_t tmp, vno, op;
    off_t off;

    off = krb5_storage_seek(dump, 0, SEEK_CUR);
    if (krb5_storage_seek(dump, 0, SEEK_SET) == -1)
        return errno;

    ret = krb5_ret_uint32(dump, &vno);
    if (ret == 0)
        ret = krb5_ret_data(dump, &data);
    if (ret == 0)
        sp = krb5_storage_from_data(&data);
    if (sp != NULL)
        ret = krb5_ret_uint32(sp, &op);
    if (ret == 0 && op != TELL_YOU_EVERYTHING)
        ret = EINVAL; /* XXX */
    if (ret == 0)
        ret = krb5_ret_uint32(sp, &tmp);
    if (ret == 0) {
        if (protocol_version == 0)
            /* Rewrite dump in protocol version 0 format */
            ret = -1;
        if (vno != tmp)
            ret = EINVAL; /* XXX */
        if (v != NULL)
            v->vno = tmp;
    } else if (protocol_version > 0)
        /* Rewrite dump in protocol version 1 format */
        ret = -1;
    if (ret == 0) {
        ret = krb5_ret_uint32(sp, &tmp);
        if (ret == 0 && v != NULL)
            v->tstamp = tmp;
        if (ret == HEIM_ERR_EOF)
            /* Rewrite dump to use version 1 format */
            ret = -1;
    }
    krb5_storage_free(sp);
    krb5_data_free(&data);
    if (krb5_storage_seek(dump, off, SEEK_SET) == -1 && ret == 0)
        return errno;
    return ret;
}

static int
send_complete1(krb5_context context, slave *s)
{
    krb5_error_code ret;
    krb5_data data;

    /* XXX Do better than assert */
    assert(s->state == IPROP_SLAVE_STATE_COMPLETE);
    assert(s->dump != NULL);

    ret = krb5_ret_data(s->dump, &data);
    if (ret == HEIM_ERR_EOF) {
        krb5_storage_free(s->dump);
        s->state = IPROP_SLAVE_STATE_IDLE;
        s->dump = NULL;
        s->version = s->dump_vno;
	slave_seen(s);
        ret = 0;	/* EOF is not an error, it's success */
        goto done;
    }
    if (ret) {
        krb5_warn(context, ret, "krb5_ret_data(dump, &data)");
        slave_dead(context, s);
        goto done;
    }

    ret = krb5_write_priv_message(context, s->ac, &s->fd, &data);
    krb5_data_free(&data);
    if (ret) {
        krb5_warn (context, ret, "krb5_write_priv_message");
        slave_dead(context, s);
        goto done;
    }

done:
    return ret;
}

static int
send_complete(krb5_context context, slave *s, const char *database,
	      iprop_version current_version, iprop_version initial_version)
{
    krb5_error_code ret;
    krb5_storage *dump = NULL;
    iprop_version version;
    uint32_t vno = 0;
    int fd = -1;
    struct stat st;
    char *dfn;

    assert(s->state == IPROP_SLAVE_STATE_IDLE); /* XXX better than assert? */

    ret = asprintf(&dfn, "%s/ipropd.dumpfile", hdb_db_dir(context));
    if (ret == -1 || !dfn) {
	krb5_warn(context, ENOMEM, "Cannot allocate memory");
	return ENOMEM;
    }

    fd = open(dfn, O_CREAT|O_RDWR, 0600);
    if (fd == -1) {
	ret = errno;
	krb5_warn(context, ret, "Cannot open/create iprop dumpfile %s", dfn);
	free(dfn);
        return ret;
    }
    free(dfn);

    dump = krb5_storage_from_fd(fd);
    if (!dump) {
	ret = errno;
	krb5_warn(context, ret, "krb5_storage_from_fd");
	goto done;
    }

    for (;;) {
	ret = flock(fd, LOCK_SH);
	if (ret == -1) {
	    ret = errno;
	    krb5_warn(context, ret, "flock(fd, LOCK_SH)");
	    goto done;
	}

	if (krb5_storage_seek(dump, 0, SEEK_SET) == (off_t)-1) {
	    ret = errno;
	    krb5_warn(context, ret, "krb5_storage_seek(dump, 0, SEEK_SET)");
	    goto done;
	}

	vno = 0;
	ret = krb5_ret_uint32(dump, &vno);
	if (ret && ret != HEIM_ERR_EOF) {
	    krb5_warn(context, ret, "krb5_ret_uint32");
	    goto done;
	}

        if (fstat(fd, &st) == -1) {
            ret = errno;
            krb5_warn(context, ret, "send_complete: could not stat dump file");
            goto done;
        }

	/*
	 * If the current dump has an appropriate version, then we can
	 * break out of the loop and send the file below.
	 */

        if (ret == 0)
            ret = get_dump_metadata(dump, &version);
	if (ret == 0 && vno != 0 && vno == version.vno &&
            st.st_mtime > initial_version.tstamp &&
            vno >= initial_version.vno) {

            if (version_lt(version, current_version) ||
                version_eq(version, current_version))
	    break;
        }

        if (verbose)
            krb5_warnx(context, "send_complete: dumping HDB");

	/*
	 * Otherwise, we may need to write a new dump file.  We
	 * obtain an exclusive lock on the fd.  Because this is
	 * not guaranteed to be an upgrade of our existing shared
	 * lock, someone else may have written a new dumpfile while
	 * we were waiting and so we must first check the vno of
	 * the dump to see if that happened.  If it did, we need
	 * to go back to the top of the loop so that we can downgrade
	 * our lock to a shared one.
	 */

	ret = flock(fd, LOCK_EX);
	if (ret == -1) {
	    ret = errno;
	    krb5_warn(context, ret, "flock(fd, LOCK_EX)");
	    goto done;
	}

	ret = krb5_storage_seek(dump, 0, SEEK_SET);
	if (ret == -1) {
	    ret = errno;
	    krb5_warn(context, ret, "krb5_storage_seek(dump, 0, SEEK_SET)");
	    goto done;
	}

	vno = 0;
	ret = krb5_ret_uint32(dump, &vno);
	if (ret && ret != HEIM_ERR_EOF) {
	    krb5_warn(context, ret, "krb5_ret_uint32");
	    goto done;
	}

        if (fstat(fd, &st) == -1) {
            ret = errno;
            krb5_warn(context, ret, "send_complete: could not stat dump file");
            goto done;
        }

	/* check if someone wrote a better version for us */
        if (ret == 0)
            ret = get_dump_metadata(dump, &version);
        if (ret == 0 && vno != 0 && vno == version.vno &&
            st.st_mtime > initial_version.tstamp &&
            version_ge(version, initial_version) &&
            version_le(version, current_version))
	    continue;

	/* Now, we know that we must write a new dump file.  */

        ret = write_dump(context, dump, database, current_version);
	if (ret)
	    goto done;

	/*
	 * And we must continue to the top of the loop so that we can
	 * downgrade to a shared lock.
	 */
    }

    /*
     * Leaving the above loop, dump should have a ptr right after the initial
     * 4 byte DB version number and we should have a shared lock on the file
     * (which we may have just created), so we are reading to simply blast
     * the data down the wire.
     */

    krb5_storage_free(s->dump);
    s->dump = dump;
    s->dump_vno = version;
    dump = NULL;

    if (ret == 0) {
        s->state = IPROP_SLAVE_STATE_COMPLETE;
        ret = send_complete1(context, s);
    }

done:
    if (fd != -1)
	close(fd);
    krb5_storage_free(dump);
    return ret;
}

static int
send_are_you_there (krb5_context context, slave *s)
{
    krb5_storage *sp;
    krb5_data data;
    char buf[4];
    int ret;

    if (s->flags & (SLAVE_F_DEAD|SLAVE_F_AYT))
	return 0;

    krb5_warnx(context, "slave %s missing, sending AYT", s->name);

    s->flags |= SLAVE_F_AYT;

    data.data = buf;
    data.length = 4;

    sp = krb5_storage_from_mem (buf, 4);
    if (sp == NULL) {
	krb5_warnx (context, "are_you_there: krb5_data_alloc");
	slave_dead(context, s);
	return 1;
    }
    ret = krb5_store_uint32(sp, ARE_YOU_THERE);
    krb5_storage_free (sp);

    if (ret == 0) {
        ret = krb5_write_priv_message(context, s->ac, &s->fd, &data);

        if (ret) {
            krb5_warn(context, ret, "are_you_there: krb5_write_priv_message");
            slave_dead(context, s);
            return 1;
        }
    }

    return 0;
}

static int
send_diffs(kadm5_server_context *server_context, slave *s, int log_fd,
	   const char *database, iprop_version current_version,
	   int do_send_complete)
{
    krb5_context context = server_context->context;
    krb5_storage *sp;
    iprop_version initial_version, initial_version2;
    iprop_version ver;
    enum kadm_ops op;
    uint32_t len;
    off_t right, left, off;
    krb5_ssize_t bytes;
    krb5_data data;
    int ret = 0;

    if (s->flags & SLAVE_F_DEAD) {
        krb5_warnx(context, "not sending diffs to dead slave %s", s->name);
        return 0;
    }

    if (version_eq(s->version, current_version)) {
	char buf[4];

	sp = krb5_storage_from_mem(buf, 4);
	if (sp == NULL)
	    krb5_errx(context, IPROPD_RESTART, "krb5_storage_from_mem");
	ret = krb5_store_uint32(sp, YOU_HAVE_LAST_VERSION);
	krb5_storage_free(sp);
	data.data   = buf;
	data.length = 4;
        if (ret == 0) {
            ret = krb5_write_priv_message(context, s->ac, &s->fd, &data);
            if (ret) {
                krb5_warn(context, ret, "send_diffs: failed to send to slave");
                slave_dead(context, s);
            }
            krb5_warnx(context, "slave %s in sync already at version %ld",
                       s->name, (long)s->version.vno);
        }
	return ret;
    }

    if (verbose)
        krb5_warnx(context, "sending diffs to live-seeming slave %s", s->name);

    /*
     * XXX The code that makes the diffs should be made a separate function,
     * then error handling (send_are_you_there() or slave_dead()) can be done
     * here.
     */

    if (flock(log_fd, LOCK_SH) == -1) {
        krb5_warn(context, errno, "could not obtain shared lock on log file");
        send_are_you_there(context, s);
        return errno;
    }
    ret = kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_FIRST,
                                   &initial_version.vno,
                                   &initial_version.tstamp);
    sp = kadm5_log_goto_end(server_context, log_fd);
    flock(log_fd, LOCK_UN);
    if (ret) {
        if (sp != NULL)
            krb5_storage_free(sp);
        krb5_warn(context, ret, "send_diffs: failed to read log");
        send_are_you_there(context, s);
        return ret;
    }

    if (do_send_complete ||
        version_gt(s->version, current_version) ||
        (s->version.vno == 0 && !(s->flags & SLAVE_F_SENT_COMPLETE)) ||
        version_lt(s->version, current_version)) {

        krb5_storage_free(sp);
        ret = send_complete(context, s, database, current_version,
                            initial_version);
        s->flags |= SLAVE_F_SENT_COMPLETE;
    }
    if (sp == NULL) {
        send_are_you_there(context, s);
        krb5_warn(context, errno ? errno : EINVAL,
                  "send_diffs: failed to read log");
        return errno ? errno : EINVAL;
    }
    /*
     * We're not holding any locks here, so we can't prevent truncations.
     *
     * We protect against this by re-checking that the initial version and
     * timestamp are the same before and after this loop.
     *
     * XXX Switch to rename-into-place for the log so we don't have to do this.
     */
    left = off = right = krb5_storage_seek(sp, 0, SEEK_CUR);
    if (right == (off_t)-1) {
        krb5_storage_free(sp);
        send_are_you_there(context, s);
        return errno;
    }
    while (off > 0) {
        ret = kadm5_log_previous(context, sp, &ver.vno, &ver.tstamp, &op,
                                 &len);
	if (ret)
	    krb5_err(context, IPROPD_RESTART, ret,
		     "send_diffs: failed to find previous entry");
	off = krb5_storage_seek(sp, -16, SEEK_CUR);
        if (off == (off_t)-1) {
            krb5_storage_free(sp);
            send_are_you_there(context, s);
            return errno;
        }

        /* We want to leave left == offset of first entry after s->version */
        if (version_gt(ver, s->version)) {
            left = off;
            continue;
        }

        /* ver <= s->version -- done */

        if (!version_eq(ver, s->version))
            do_send_complete = 1;
        break;
    }

    /* If we've reached the uber record, send the complete database */
    if ((off == 0 && op == kadm_nop) || (ver.vno == 0 && op == kadm_nop) ||
        do_send_complete ||
        /* left == right shouldn't happen; see YOU_HAVE_LAST_VERSION above */
        left >= right) {
        krb5_storage_free(sp);
        krb5_warnx(context,
                   "slave %s (version %lu, time %lu) out of sync with master "
                   "(first version in log %lu, time %lu), sending complete "
                   "database", s->name,
                   (unsigned long)s->version.vno,
                   (unsigned long)s->version.tstamp,
                   (unsigned long)ver.vno, (unsigned long)ver.tstamp);
        return send_complete(context, s, database, current_version,
                             initial_version);
    }

    assert(version_eq(ver, s->version));

    krb5_warnx(context,
	       "syncing slave %s from version %lu to version %lu",
	       s->name, (unsigned long)s->version.vno,
	       (unsigned long)current_version.vno);

    ret = krb5_data_alloc (&data, right - left + 4);
    if (ret) {
	krb5_storage_free(sp);
	krb5_warn (context, ret, "send_diffs: krb5_data_alloc");
        send_are_you_there(context, s);
	return 1;
    }
    if (krb5_storage_seek(sp, left, SEEK_SET) == (off_t)-1)
        krb5_err(context, IPROPD_RESTART, errno, "krb5_storage_seek");
    bytes = krb5_storage_read(sp, (char *)data.data + 4, data.length - 4);
    krb5_storage_free(sp);
    if (bytes != data.length - 4) {
        krb5_warnx(context, "iprop log truncated while sending diffs to "
                   "slave??  ver = %lu", (unsigned long)ver.vno);
        send_are_you_there(context, s);
        return 1;
    }

    /*
     * Check that we have the same log initial version and timestamp now as
     * when we dropped the shared lock on the log file!  Else we could be
     * sending garbage to the slave.
     */
    if (flock(log_fd, LOCK_SH) == -1) {
        krb5_warn(context, errno, "could not obtain shared lock on log file");
        send_are_you_there(context, s);
        return 1;
    }
    ret = kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_FIRST,
                                   &initial_version2.vno,
                                   &initial_version2.tstamp);
    flock(log_fd, LOCK_UN);
    if (ret) {
        krb5_warn(context, ret,
                   "send_diffs: failed to read log while producing diffs");
        send_are_you_there(context, s);
        return 1;
    }
    if (!version_eq(initial_version, initial_version2)) {
        krb5_warn(context, ret,
                   "send_diffs: log truncated while producing diffs");
        send_are_you_there(context, s);
        return 1;
    }

    sp = krb5_storage_from_data (&data);
    if (sp == NULL) {
	krb5_warnx (context, "send_diffs: krb5_storage_from_data");
        send_are_you_there(context, s);
	return 1;
    }
    krb5_store_uint32 (sp, FOR_YOU);
    krb5_storage_free(sp);

    ret = krb5_write_priv_message(context, s->ac, &s->fd, &data);
    krb5_data_free(&data);

    if (ret) {
	krb5_warn (context, ret, "send_diffs: krb5_write_priv_message");
	slave_dead(context, s);
	return 1;
    }
    slave_seen(s);

    s->version = current_version;

    krb5_warnx(context, "slave %s is now up to date (%u)", s->name,
               s->version.vno);

    return 0;
}

static int
send_what_do_you_mean(kadm5_server_context *server_context, slave *s)
{
    krb5_context context = server_context->context;
    krb5_storage *sp;
    krb5_data data;
    char buf[sizeof(uint32_t) * 2];
    int ret;

    if (s->flags & SLAVE_F_DEAD)
	return 0;

    data.data = buf;
    data.length = sizeof(buf);
    sp = krb5_storage_from_mem(buf, sizeof(buf));
    if (sp == NULL) {
	krb5_warnx (context, "what_do_you_mean: krb5_data_alloc");
	slave_dead(context, s);
	return 1;
    }
    ret = krb5_store_uint32(sp, WHAT_DO_YOU_MEAN);
    if (ret == 0)
        ret = krb5_store_uint32(sp, IPROP_PROTOCOL_VERSION);
    krb5_storage_free(sp);
    if (ret == 0)
        ret = krb5_write_priv_message(context, s->ac, &s->fd, &data);
    if (ret == 0)
        return 0;
    krb5_warn(context, ret, "what_do_you_mean: krb5_write_priv_message");
    slave_dead(context, s);
    return 1;
}

static int
process_msg(kadm5_server_context *server_context, slave *s, int log_fd,
	    const char *database, iprop_version current_version)
{
    krb5_context context = server_context->context;
    int ret = 0;
    int do_send_complete = 0;
    krb5_data out;
    krb5_storage *sp;
    iprop_version slave_last_version = { 0, 0 };
    uint32_t op, slave_protocol_version;

    /*
     * Slave is not allowed to send messages while we're sending it diffs or
     * complete.
     */
    if (s->state != IPROP_SLAVE_STATE_IDLE) {
        krb5_warn(context, ret, "slave %s sent message while we are sending "
                  "complete; disconnecting it", s->name);
        return 1;
    }

    ret = krb5_read_priv_message(context, s->ac, &s->fd, &out);
    if(ret) {
	krb5_warn(context, ret, "error reading message from %s", s->name);
	return 1;
    }

    sp = krb5_storage_from_mem(out.data, out.length);
    if (sp == NULL) {
	krb5_warnx(context, "process_msg: no memory");
	krb5_data_free(&out);
	return 1;
    }
    if (krb5_ret_uint32(sp, &op) != 0) {
	krb5_warnx(context, "process_msg: client send too short command");
	krb5_data_free(&out);
	return 1;
    }
    switch (op) {
    case TELL_ME_EVERYTHING:
        if (protocol_version > 0) {
            s->version.vno = 0;
            s->version.tstamp = 0;
            ret = send_diffs(server_context, s, log_fd, database,
                             current_version, 1);
        } /* else silence */
        break;
    case I_HAVE :
	ret = krb5_ret_uint32(sp, &slave_last_version.vno);
	if (ret != 0) {
	    krb5_warnx(context, "process_msg: client send too little I_HAVE data");
	    break;
	}
        slave_protocol_version = 0;
        if (protocol_version > 0) {
            if (ret == 0)
                ret = krb5_ret_uint32(sp, &slave_last_version.tstamp);
            if (ret == 0) {
                ret = krb5_ret_uint32(sp, &slave_protocol_version);
                if (ret == 0)
                    s->protocol_version = min(protocol_version, slave_protocol_version);
                if (ret)
                    slave_protocol_version = 0;
            }
            if (ret == HEIM_ERR_EOF) {
                slave_protocol_version = 0;
                ret = 0;
            }
        }
        s->protocol_version = slave_protocol_version;
	if (s->version.vno == 0 && slave_last_version.vno != 0) {
            /* Slave just connected, and has an HDB and iprop log */
	    if (version_gt(slave_last_version, current_version)) {
		krb5_warnx(context, "Slave %s (version %u, time %u) has later version "
			   "than the master (version %u, time %u) OUT OF SYNC",
                           s->name, slave_last_version.vno,
                           slave_last_version.tstamp, current_version.vno,
                           current_version.tstamp);
                do_send_complete = 1;
	    }
            if (verbose)
                krb5_warnx(context, "slave state %s updated from %u to %u",
                           s->name, s->version.vno, slave_last_version.vno);
	    s->version = slave_last_version;
	}
	if (version_lt(slave_last_version, s->version)) {
	    krb5_warnx(context, "Slave %s claims to be at version %u "
                       "but we had sent it version %u", s->name,
                       slave_last_version.vno, s->version.vno);
            s->version = slave_last_version;
            do_send_complete = 1;
	}

        if (!version_eq(s->version, slave_last_version)) {
	    krb5_warnx(context, "Slave %s claims to be at version %u:%u "
                       "but we had sent it version %u:%u", s->name,
                       slave_last_version.vno, slave_last_version.tstamp,
                       s->version.vno, s->version.tstamp);
        }
        ret = send_diffs(server_context, s, log_fd, database, current_version,
                         do_send_complete);
        break;
    case WHAT_DO_YOU_MEAN:
	krb5_warnx(context, "Slave %s did not understand our last message", s->name);
        break;
    case ARE_YOU_THERE:
    case FOR_YOU :
	krb5_warnx(context, "Ignoring unexpected command %d", op);
        if (protocol_version > 0)
            ret = send_what_do_you_mean(server_context, s);
	break;
    default :
	krb5_warnx(context, "Ignoring unknown command %d", op);
        if (protocol_version > 0)
            ret = send_what_do_you_mean(server_context, s);
	break;
    }

    krb5_data_free(&out);
    krb5_storage_free(sp);

    slave_seen(s);

    return ret;
}

#define SLAVE_NAME	"Name"
#define SLAVE_ADDRESS	"Address"
#define SLAVE_VERSION	"Version"
#define SLAVE_STATUS	"Status"
#define SLAVE_SEEN	"Last Seen"

static FILE *
open_stats(krb5_context context)
{
    char *statfile = NULL;
    const char *fn = NULL;
    FILE *out = NULL;

    /*
     * krb5_config_get_string_default() returs default value as-is,
     * delay free() of "statfile" until we're done with "fn".
     */
    if (slave_stats_file)
	fn = slave_stats_file;
    else if (asprintf(&statfile,  "%s/slaves-stats", hdb_db_dir(context)) != -1
	     && statfile != NULL)
	fn = krb5_config_get_string_default(context,
					    NULL,
					    statfile,
					    "kdc",
					    "iprop-stats",
					    NULL);
    if (fn != NULL)
	out = fopen(fn, "w");
    if (statfile != NULL)
	free(statfile);
    return out;
}

static void
write_master_down(krb5_context context)
{
    char str[100];
    time_t t = time(NULL);
    FILE *fp;

    fp = open_stats(context);
    if (fp == NULL)
	return;
    krb5_format_time(context, t, str, sizeof(str), TRUE);
    fprintf(fp, "master down at %s\n", str);

    fclose(fp);
}

static void
write_stats(krb5_context context, slave *slaves, iprop_version current_version)
{
    char str[100];
    rtbl_t tbl;
    time_t t = time(NULL);
    FILE *fp;

    fp = open_stats(context);
    if (fp == NULL)
	return;

    krb5_format_time(context, t, str, sizeof(str), TRUE);
    fprintf(fp, "Status for slaves, last updated: %s\n\n", str);

    fprintf(fp, "Master version: %lu.%lu\n\n",
            (unsigned long)current_version.vno,
            (unsigned long)current_version.tstamp);

    tbl = rtbl_create();
    if (tbl == NULL) {
	fclose(fp);
	return;
    }

    rtbl_add_column(tbl, SLAVE_NAME, 0);
    rtbl_add_column(tbl, SLAVE_ADDRESS, 0);
    rtbl_add_column(tbl, SLAVE_VERSION, RTBL_ALIGN_RIGHT);
    rtbl_add_column(tbl, SLAVE_STATUS, 0);
    rtbl_add_column(tbl, SLAVE_SEEN, 0);

    rtbl_set_prefix(tbl, "  ");
    rtbl_set_column_prefix(tbl, SLAVE_NAME, "");

    while (slaves) {
	krb5_address addr;
	krb5_error_code ret;
	rtbl_add_column_entry(tbl, SLAVE_NAME, slaves->name);
	ret = krb5_sockaddr2address (context,
				     (struct sockaddr*)&slaves->addr, &addr);
	if(ret == 0) {
	    krb5_print_address(&addr, str, sizeof(str), NULL);
	    krb5_free_address(context, &addr);
	    rtbl_add_column_entry(tbl, SLAVE_ADDRESS, str);
	} else
	    rtbl_add_column_entry(tbl, SLAVE_ADDRESS, "<unknown>");

	snprintf(str, sizeof(str), "%lu.%lu",
                 (unsigned long)slaves->version.vno,
                 (unsigned long)slaves->version.tstamp);
	rtbl_add_column_entry(tbl, SLAVE_VERSION, str);

	if (slaves->flags & SLAVE_F_DEAD)
	    rtbl_add_column_entry(tbl, SLAVE_STATUS, "Down");
	else
	    rtbl_add_column_entry(tbl, SLAVE_STATUS, "Up");

	ret = krb5_format_time(context, slaves->seen, str, sizeof(str), TRUE);
	rtbl_add_column_entry(tbl, SLAVE_SEEN, str);

	slaves = slaves->next;
    }

    rtbl_format(tbl, fp);
    rtbl_destroy(tbl);

    fclose(fp);
}


static char sHDB[] = "HDBGET:";
static char *realm;
static int version_flag;
static int help_flag;
static char *keytab_str = sHDB;
static char *database;
static char *config_file;
static char *port_str;
static int detach_from_console;
static int daemon_child = -1;
static int timeout = 30;

static struct getargs args[] = {
    { "config-file", 'c', arg_string, &config_file, NULL, NULL },
    { "realm", 'r', arg_string, &realm, NULL, NULL },
    { "keytab", 'k', arg_string, &keytab_str,
      "keytab to get authentication from", "kspec" },
    { "database", 'd', arg_string, &database, "database", "file"},
    { "slave-stats-file", 0, arg_string, rk_UNCONST(&slave_stats_file),
      "file for slave status information", "file"},
    { "time-missing", 0, arg_string, rk_UNCONST(&slave_time_missing),
      "time before slave is polled for presence", "time"},
    { "time-gone", 0, arg_string, rk_UNCONST(&slave_time_gone),
      "time of inactivity after which a slave is considered gone", "time"},
    { "timeout", 0, arg_integer, &timeout,
       "event loop timeout (seconds) (default: 30)", NULL },
    { "protocol-version", 0, arg_integer, &protocol_version,
      "highest iprop protocol version served (default: 1)", NULL },
    { "port", 0, arg_string, &port_str,
      "port ipropd will listen to", "port"},
    { "detach", 0, arg_flag, &detach_from_console,
      "detach from console", NULL },
    { "daemon-child",       0 ,      arg_integer, &daemon_child,
      "private argument, do not use", NULL },
    { "hostname", 0, arg_string, rk_UNCONST(&master_hostname),
      "hostname of master (if not same as hostname)", "hostname" },
    { "verbose", 0, arg_flag, &verbose, NULL, NULL },
    { "version", 0, arg_flag, &version_flag, NULL, NULL },
    { "help", 0, arg_flag, &help_flag, NULL, NULL }
};
static int num_args = sizeof(args) / sizeof(args[0]);

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    void *kadm_handle;
    kadm5_server_context *server_context;
    kadm5_config_params conf;
    krb5_socket_t signal_fd, listen_fd;
    int log_fd;
    slave *slaves = NULL;
    iprop_version current_version = { 0, 0 };
    iprop_version old_version = { 0, 0 };
    krb5_keytab keytab;
    char **files;
    int aret;
    int optidx = 0;
    int restarter_fd = -1;
    struct stat st;

    setprogname(argv[0]);

    if (getarg(args, num_args, argc, argv, &optidx))
        krb5_std_usage(1, args, num_args);

    if (help_flag)
	krb5_std_usage(0, args, num_args);

    if (version_flag) {
	print_version(NULL);
	exit(0);
    }

    if (protocol_version < 0 || protocol_version > IPROP_PROTOCOL_VERSION)
        errx(1, "invalid iprop protocol version number (min 0, max %d)",
             IPROP_PROTOCOL_VERSION);

    if (detach_from_console && daemon_child == -1)
        roken_detach_prep(argc, argv, "--daemon-child");
    rk_pidfile(NULL);

    ret = krb5_init_context(&context);
    if (ret)
        errx(1, "krb5_init_context failed: %d", ret);

    setup_signal();

    if (config_file == NULL) {
	aret = asprintf(&config_file, "%s/kdc.conf", hdb_db_dir(context));
	if (aret == -1 || config_file == NULL)
	    errx(1, "out of memory");
    }

    ret = krb5_prepend_config_files_default(config_file, &files);
    if (ret)
	krb5_err(context, 1, ret, "getting configuration files");

    ret = krb5_set_config_files(context, files);
    krb5_free_config_files(files);
    if (ret)
	krb5_err(context, 1, ret, "reading configuration files");

    time_before_gone = parse_time (slave_time_gone,  "s");
    if (time_before_gone < 0)
	krb5_errx (context, 1, "couldn't parse time: %s", slave_time_gone);
    time_before_missing = parse_time (slave_time_missing,  "s");
    if (time_before_missing < 0)
	krb5_errx (context, 1, "couldn't parse time: %s", slave_time_missing);

    krb5_openlog(context, "ipropd-master", &log_facility);
    krb5_set_warn_dest(context, log_facility);

    ret = krb5_kt_register(context, &hdb_get_kt_ops);
    if(ret)
	krb5_err(context, 1, ret, "krb5_kt_register");

    ret = krb5_kt_resolve(context, keytab_str, &keytab);
    if(ret)
	krb5_err(context, 1, ret, "krb5_kt_resolve: %s", keytab_str);

    memset(&conf, 0, sizeof(conf));
    if(realm) {
	conf.mask |= KADM5_CONFIG_REALM;
	conf.realm = realm;
    }
    ret = kadm5_init_with_skey_ctx (context,
				    KADM5_ADMIN_SERVICE,
				    NULL,
				    KADM5_ADMIN_SERVICE,
				    &conf, 0, 0,
				    &kadm_handle);
    if (ret)
	krb5_err (context, 1, ret, "kadm5_init_with_password_ctx");

    server_context = (kadm5_server_context *)kadm_handle;

    log_fd = open (server_context->log_context.log_file, O_RDONLY, 0);
    if (log_fd < 0)
	krb5_err (context, 1, errno, "open %s",
		  server_context->log_context.log_file);

    if (fstat(log_fd, &st) == -1)
        krb5_err(context, 1, errno, "stat %s",
                 server_context->log_context.log_file);

    if (flock(log_fd, LOCK_SH) == -1)
        krb5_err(context, 1, errno, "shared flock %s",
                 server_context->log_context.log_file);
    kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_LAST,
                             &current_version.vno, &current_version.tstamp);
    flock(log_fd, LOCK_UN);
    old_version = current_version;

    signal_fd = make_signal_socket (context);
    listen_fd = make_listen_socket (context, port_str);

    krb5_warnx(context, "ipropd-master started at version: %lu.%lu",
	       (unsigned long)current_version.vno,
               (unsigned long)current_version.tstamp);

    roken_detach_finish(NULL, daemon_child);
    restarter_fd = restarter(context, NULL);

    while (exit_flag == 0){
	slave *p;
	fd_set readset, writeset, exceptset;
	int max_fd = 0;
        int do_recovery = 0;
	struct timeval to = {timeout, 0};
	uint32_t vers;
        struct stat st2;
        time_t last_recovery_check = 0;

#ifndef NO_LIMIT_FD_SETSIZE
	if (signal_fd >= FD_SETSIZE || listen_fd >= FD_SETSIZE ||
            restarter_fd >= FD_SETSIZE)
	    krb5_errx (context, IPROPD_RESTART, "fd too large");
#endif

	FD_ZERO(&readset);
	FD_ZERO(&writeset);
	FD_ZERO(&exceptset);
	FD_SET(signal_fd, &readset);
	max_fd = max(max_fd, signal_fd);
	FD_SET(listen_fd, &readset);
	max_fd = max(max_fd, listen_fd);
        if (restarter_fd > -1) {
            FD_SET(restarter_fd, &readset);
            max_fd = max(max_fd, restarter_fd);
        }

	for (p = slaves; p != NULL; p = p->next) {
	    if (p->flags & SLAVE_F_DEAD)
		continue;
	    FD_SET(p->fd, &readset);
	    FD_SET(p->fd, &exceptset);
	    max_fd = max(max_fd, p->fd);
            if (p->state == IPROP_SLAVE_STATE_COMPLETE)
                FD_SET(p->fd, &writeset);
	}

        ret = select(max_fd + 1, &readset, &writeset, &exceptset, &to);
	if (ret < 0) {
	    if (errno == EINTR)
		continue;
            krb5_err(context, IPROPD_RESTART, errno, "select");
	}

        if (ret > 0 && FD_ISSET(restarter_fd, &readset)) {
            exit_flag = SIGTERM;
            break;
        }

        /* [Re-]open iprop log as needed */
        if (stat(server_context->log_context.log_file, &st2) == -1) {
            krb5_warn(context, errno, "could not stat log file by path");
            st2 = st;
        }

        if (st2.st_dev != st.st_dev || st2.st_ino != st.st_ino) {
            (void) close(log_fd);
            do_recovery = 1;

            log_fd = open(server_context->log_context.log_file, O_RDONLY, 0);
            if (log_fd < 0)
                krb5_err(context, 1, IPROPD_RESTART_SLOW, "open %s",
                          server_context->log_context.log_file);

            if (fstat(log_fd, &st) == -1)
                krb5_err(context, IPROPD_RESTART_SLOW, errno, "stat %s",
                         server_context->log_context.log_file);

            if (flock(log_fd, LOCK_SH) == -1)
                krb5_err(context, IPROPD_RESTART, errno, "shared flock %s",
                         server_context->log_context.log_file);
            kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_LAST,
                                     &current_version.vno, &current_version.tstamp);
            flock(log_fd, LOCK_UN);
        } else if (st2.st_mtime > last_recovery_check &&
                   time(NULL) - last_recovery_check > timeout)
            do_recovery = 1;

	if (ret == 0 || do_recovery) {
            /*
             * Recover from incomplete transactions.
             *
             * If we only did this on select() timeout then a constant stream
             * of slave connect/disconnect events could make us miss the need
             * to recover from failed transactions more often.  For this
             * reason, whenever the log file identity has changed or its mtime
             * has changed enough, we will do recovery.
             */
            last_recovery_check = st2.st_mtime;
            if (kadm5_log_init_nb(server_context) == 0)
                kadm5_log_end(server_context);

	    if (flock(log_fd, LOCK_SH) == -1)
                krb5_err(context, IPROPD_RESTART, errno,
                         "could not lock log file");
	    kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_LAST,
                                     &current_version.vno, &current_version.tstamp);
	    flock(log_fd, LOCK_UN);

	    if (current_version.vno > old_version.vno) {
		krb5_warnx(context,
			   "Missed a signal, updating slaves %lu to %lu",
			   (unsigned long)old_version.vno,
			   (unsigned long)current_version.vno);
		for (p = slaves; p != NULL; p = p->next) {
		    if (p->flags & SLAVE_F_DEAD)
			continue;
		    send_diffs(server_context, p, log_fd, database,
                               current_version, 0);
		}
                old_version = current_version;
	    }
	}

        if (ret == 0)
            continue;

	if (FD_ISSET(signal_fd, &readset)) {
#ifndef NO_UNIX_SOCKETS
	    struct sockaddr_un peer_addr;
#else
	    struct sockaddr_storage peer_addr;
#endif
	    socklen_t peer_len = sizeof(peer_addr);

	    if(recvfrom(signal_fd, (void *)&vers, sizeof(vers), 0,
			(struct sockaddr *)&peer_addr, &peer_len) < 0) {
		krb5_warn (context, errno, "recvfrom");
		continue;
	    }
	    old_version = current_version;
	    if (flock(log_fd, LOCK_SH) == -1)
                krb5_err(context, IPROPD_RESTART, errno, "shared flock %s",
                         server_context->log_context.log_file);
            kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_LAST,
                                     &current_version.vno,
                                     &current_version.tstamp);
	    flock(log_fd, LOCK_UN);
	    if (!version_eq(current_version, old_version)) {
                /*
                 * If current_version < old_version then the log got
                 * truncated and we'll end up doing full propagations.
                 *
                 * Truncating the log when the current version is
                 * numerically small can lead to race conditions when talking
                 * to downrev peers.
                 */
		krb5_warnx(context,
			   "Got a signal, updating slaves %lu to %lu",
			   (unsigned long)old_version.vno,
			   (unsigned long)current_version.vno);
		for (p = slaves; p != NULL; p = p->next) {
		    if (p->flags & SLAVE_F_DEAD)
			continue;
		    send_diffs(server_context, p, log_fd, database,
                               current_version, 0);
		}
	    } else {
		krb5_warnx(context,
			   "Got a signal, but no update in log version %lu",
			   (unsigned long)current_version.vno);
	    }
        }

        /* Service connected slaves */
	for(p = slaves; p != NULL; p = p->next) {
	    if (p->flags & SLAVE_F_DEAD)
	        continue;

            if (FD_ISSET(p->fd, &readset) &&
                process_msg(server_context, p, log_fd, database,
                            current_version)) {
                /* Protocol or I/O error?  Disconnect the slave */
                slave_dead(context, p);
                continue;
            }

            /*
             * If we're looking for write events it's so we can continue the
             * chunked up send_complete().
             */
            if (FD_ISSET(p->fd, &writeset) && p->state == IPROP_SLAVE_STATE_COMPLETE)
                send_complete1(context, p);

	    if (FD_ISSET(p->fd, &exceptset) || slave_gone_p(p))
		slave_dead(context, p);
            else if (slave_missing_p(p))
		send_are_you_there(context, p);
	}

        /* Accept new slaves */
	if (FD_ISSET(listen_fd, &readset))
	    add_slave (context, keytab, &slaves, listen_fd);

	write_stats(context, slaves, current_version);
    }

    if(exit_flag == SIGINT || exit_flag == SIGTERM)
	krb5_warnx(context, "%s terminated", getprogname());
#ifdef SIGXCPU
    else if(exit_flag == SIGXCPU)
	krb5_warnx(context, "%s CPU time limit exceeded", getprogname());
#endif
    else
	krb5_warnx(context, "%s unexpected exit reason: %ld",
		   getprogname(), (long)exit_flag);

    write_master_down(context);

    return 0;
}
