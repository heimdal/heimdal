/*
 * Copyright (c) 2000 - 2004 Kungliga Tekniska Högskolan
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

#include "kadmin_locl.h"
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef _WIN32
#include <process.h>
#endif

extern int daemon_child;
extern krb5_keytab keytab;
extern int readonly_flag;

struct kadm_port {
    char *port;
    unsigned short def_port;
    struct kadm_port *next;
} *kadm_ports;

static void
add_kadm_port(krb5_context contextp, const char *service, unsigned int port)
{
    struct kadm_port *p;
    p = malloc(sizeof(*p));
    if(p == NULL) {
	krb5_warnx(contextp, "failed to allocate %lu bytes\n",
		   (unsigned long)sizeof(*p));
	return;
    }

    p->port = strdup(service);
    p->def_port = port;

    p->next = kadm_ports;
    kadm_ports = p;
}

static void
add_standard_ports (krb5_context contextp)
{
    if (krb5_config_get_bool(context, NULL, "libdefaults", "block_dns",
	    NULL))
	add_kadm_port(contextp, "749", 749);
    else
	add_kadm_port(contextp, "kerberos-adm", 749);
}

/*
 * parse the set of space-delimited ports in `str' and add them.
 * "+" => all the standard ones
 * otherwise it's port|service[/protocol]
 */

void
parse_ports(krb5_context contextp, const char *str)
{
    char p[128];

    while(strsep_copy(&str, " \t", p, sizeof(p)) != -1) {
	if(strcmp(p, "+") == 0)
	    add_standard_ports(contextp);
	else
	    add_kadm_port(contextp, p, 0);
    }
}

/*
 * Threaded model for kadmind.
 *
 * We spawn a thread per connection rather than forking. This:
 * - Works on all platforms (including Windows)
 * - Has lower overhead than fork()
 * - Simplifies the codebase (one code path)
 *
 * Thread safety is ensured by:
 * - Per-connection krb5_context, kadm5_server_context, auth_context
 * - HDB uses HEIMDAL_MUTEX for database locking
 * - Shared config (keytab, readonly_flag) is read-only after init
 */

#include <heim_threads.h>

sig_atomic_t term_flag = 0;
sig_atomic_t doing_useful_work = 0;

static HEIMDAL_MUTEX thread_count_lock = HEIMDAL_MUTEX_INITIALIZER;
static unsigned int active_thread_count = 0;

struct client_thread_arg {
    krb5_context context;
    krb5_socket_t socket;
    krb5_keytab keytab;
    int readonly;
};

static void *
client_thread_func(void *arg)
{
    struct client_thread_arg *cta = (struct client_thread_arg *)arg;

    doing_useful_work = 1;
    kadmind_loop(cta->context, cta->keytab, cta->socket, cta->readonly);
    doing_useful_work = 0;

    rk_closesocket(cta->socket);
    free(cta);

    HEIMDAL_MUTEX_lock(&thread_count_lock);
    active_thread_count--;
    HEIMDAL_MUTEX_unlock(&thread_count_lock);

    return NULL;
}

static void
wait_for_all_threads(krb5_context contextp, unsigned int timeout_sec)
{
    time_t deadline = time(NULL) + timeout_sec;
    unsigned int count;

    /*
     * For want of a timedwait cond var operation we just use a lock and
     * microsleeps to wait up to timeout_sec and we _exit() if we pass that
     * deadline.
     *
     * This allows us to exit even if threads are blocked in I/O and won't
     * check term_flag.  Ideally we'd add "interruptible" variants of
     * krb5_net_read() and krb5_net_write() that take a second FD where the
     * second FD is a pipe, and then block in select()/poll()/whatever()
     * waiting for I/O on either FD, and if the pipe ever has data to read then
     * return an error that indicates that we want to exit (maybe even EPIPE!).
     */
    for (;;) {
        HEIMDAL_MUTEX_lock(&thread_count_lock);
        count = active_thread_count;
        HEIMDAL_MUTEX_unlock(&thread_count_lock);

        if (count == 0)
            return;
        if (time(NULL) >= deadline) {
            krb5_warnx(contextp,
                       "timeout waiting for %u threads, forcing exit",
                       count);
            _exit(0);
        }
        usleep(100000); /* 100ms */
    }
}

#ifdef _WIN32
static BOOL WINAPI
console_handler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT ||
        ctrl_type == CTRL_CLOSE_EVENT) {
        term_flag = 1;
        return TRUE;
    }
    return FALSE;
}
#else
static RETSIGTYPE
terminate(int sig)
{
    term_flag = 1;
    SIGRETURN(0);
}
#endif

static int
spawn_child(krb5_context contextp, krb5_socket_t *socks,
	    unsigned int num_socks, int this_sock)
{
    int e;
    struct sockaddr_storage __ss;
    struct sockaddr *sa = (struct sockaddr *)&__ss;
    socklen_t sa_size = sizeof(__ss);
    krb5_socket_t s;
    krb5_address addr;
    char buf[128];
    size_t buf_len;
    struct client_thread_arg *cta;
    HEIMDAL_THREAD_ID thread;

    s = accept(socks[this_sock], sa, &sa_size);
    if(rk_IS_BAD_SOCKET(s)) {
	krb5_warn(contextp, rk_SOCK_ERRNO, "accept");
	return 1;
    }
    e = krb5_sockaddr2address(contextp, sa, &addr);
    if(e)
	krb5_warn(contextp, e, "krb5_sockaddr2address");
    else {
	e = krb5_print_address (&addr, buf, sizeof(buf),
				&buf_len);
	if(e)
	    krb5_warn(contextp, e, "krb5_print_address");
	else
	    krb5_warnx(contextp, "connection from %s", buf);
	krb5_free_address(contextp, &addr);
    }

    cta = malloc(sizeof(*cta));
    if (cta == NULL) {
        krb5_warn(contextp, ENOMEM, "malloc");
        rk_closesocket(s);
        return 1;
    }

    cta->context = contextp;
    cta->socket = s;
    cta->keytab = keytab;
    cta->readonly = readonly_flag;

    HEIMDAL_MUTEX_lock(&thread_count_lock);
    active_thread_count++;
    HEIMDAL_MUTEX_unlock(&thread_count_lock);

    e = HEIMDAL_THREAD_create(&thread, client_thread_func, cta);
    if (e) {
        krb5_warn(contextp, e, "HEIMDAL_THREAD_create");
        HEIMDAL_MUTEX_lock(&thread_count_lock);
        active_thread_count--;
        HEIMDAL_MUTEX_unlock(&thread_count_lock);
        free(cta);
        rk_closesocket(s);
        return 1;
    }

    HEIMDAL_THREAD_detach(thread);
    return 1;
}

static void
wait_for_connection(krb5_context contextp,
		    krb5_socket_t *socks, unsigned int num_socks)
{
    unsigned int i;
    int e;
    fd_set orig_read_set, read_set;
    int max_fd = -1;
    struct timeval tv;

    FD_ZERO(&orig_read_set);

    for(i = 0; i < num_socks; i++) {
#ifdef FD_SETSIZE
	if (socks[i] >= FD_SETSIZE)
	    errx (1, "fd too large");
#endif
	FD_SET(socks[i], &orig_read_set);
	max_fd = max(max_fd, socks[i]);
    }

#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGTERM, terminate);
    signal(SIGINT, terminate);
    signal(SIGPIPE, SIG_IGN);
#endif

    while (term_flag == 0) {
        read_set = orig_read_set;
        /* Use a timeout so we can check term_flag periodically */
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        e = select(max_fd + 1, &read_set, NULL, NULL, &tv);
        if(rk_IS_SOCKET_ERROR(e)) {
            if(rk_SOCK_ERRNO != EINTR)
                krb5_warn(contextp, rk_SOCK_ERRNO, "select");
        } else if(e > 0) {
            for(i = 0; i < num_socks; i++) {
                if(FD_ISSET(socks[i], &read_set))
                    spawn_child(contextp, socks, num_socks, i);
            }
        }
    }

    krb5_warnx(contextp, "kadmind: shutting down");
    /* Wait for client threads to finish, with timeout */
    wait_for_all_threads(contextp, 5);

    exit(0);
}


void
start_server(krb5_context contextp, const char *port_str)
{
    int e;
    struct kadm_port *p;

    krb5_socket_t *socks = NULL, *tmp;
    unsigned int num_socks = 0;
    int i;

    if (port_str == NULL)
	port_str = "+";

    parse_ports(contextp, port_str);

    for(p = kadm_ports; p; p = p->next) {
	struct addrinfo hints, *ai, *ap;
	char portstr[32];
	memset (&hints, 0, sizeof(hints));
	hints.ai_flags    = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	if (krb5_config_get_bool(context, NULL, "libdefaults", "block_dns",
		NULL)) {
	    hints.ai_flags &= ~AI_CANONNAME;
	    hints.ai_flags |= AI_NUMERICHOST|AI_NUMERICSERV;
	}
	e = getaddrinfo(NULL, p->port, &hints, &ai);
	if(e) {
	    snprintf(portstr, sizeof(portstr), "%u", p->def_port);
	    e = getaddrinfo(NULL, portstr, &hints, &ai);
	}

	if(e) {
	    krb5_warn(contextp, krb5_eai_to_heim_errno(e, errno),
		      "%s", portstr);
	    continue;
	}
	i = 0;
	for(ap = ai; ap; ap = ap->ai_next)
	    i++;
	tmp = realloc(socks, (num_socks + i) * sizeof(*socks));
	if(tmp == NULL)
	    krb5_err(contextp, 1, errno, "failed to reallocate %lu bytes",
		     (unsigned long)(num_socks + i) * sizeof(*socks));
	socks = tmp;
	for(ap = ai; ap; ap = ap->ai_next) {
	    krb5_socket_t s = socket(ap->ai_family, ap->ai_socktype, ap->ai_protocol);
	    if(rk_IS_BAD_SOCKET(s)) {
		krb5_warn(contextp, rk_SOCK_ERRNO, "socket");
		continue;
	    }

	    socket_set_reuseaddr(s, 1);
	    socket_set_ipv6only(s, 1);

	    if (rk_IS_SOCKET_ERROR(bind (s, ap->ai_addr, ap->ai_addrlen))) {
		krb5_warn(contextp, rk_SOCK_ERRNO, "bind");
		rk_closesocket(s);
		continue;
	    }
	    if (rk_IS_SOCKET_ERROR(listen (s, SOMAXCONN))) {
		krb5_warn(contextp, rk_SOCK_ERRNO, "listen");
		rk_closesocket(s);
		continue;
	    }

	    socket_set_keepalive(s, 1);
	    socks[num_socks++] = s;
	}
	freeaddrinfo (ai);
    }
    if(num_socks == 0)
	krb5_errx(contextp, 1, "no sockets to listen to - exiting");

    roken_detach_finish(NULL, daemon_child);

    wait_for_connection(contextp, socks, num_socks);
    free(socks);
}
