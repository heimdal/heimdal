/*
 * Copyright (c) 2005 - 2006 Kungliga Tekniska Högskolan
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

#include "hx_locl.h"

/*
 * lib/hcrypto.ui.c code here
 */
#include <signal.h>
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#define UI_UTIL_FLAG_VERIFY         0x1 /* ask to verify password */
#define UI_UTIL_FLAG_VERIFY_SILENT  0x2 /* silence on verify failure */

#ifdef HAVE_CONIO_H
#include <conio.h>
#endif

static sig_atomic_t intr_flag;

static void
intr(int sig)
{
    intr_flag++;
}

#ifdef HAVE_CONIO_H

/*
 * Windows does console slightly different then then unix case.
 */

static int
read_string(const char *preprompt, const char *prompt,
	    char *buf, size_t len, int echo)
{
    int of = 0;
    int c;
    char *p;
    void (*oldsigintr)(int);

    _cprintf("%s%s", preprompt, prompt);

    oldsigintr = signal(SIGINT, intr);

    p = buf;
    while(intr_flag == 0){
	c = ((echo)? _getche(): _getch());
	if(c == '\n' || c == '\r')
	    break;
	if(of == 0)
	    *p++ = c;
	of = (p == buf + len);
    }
    if(of)
	p--;
    *p = 0;

    if(echo == 0){
	printf("\n");
    }

    signal(SIGINT, oldsigintr);

    if(intr_flag)
	return -2;
    if(of)
	return -1;
    return 0;
}

#else /* !HAVE_CONIO_H */

#ifndef NSIG
#define NSIG 47
#endif

static int
read_string(const char *preprompt, const char *prompt,
	    char *buf, size_t len, int echo)
{
    struct sigaction sigs[NSIG];
    int oksigs[NSIG];
    struct sigaction sa;
    FILE *tty;
    int ret = 0;
    int of = 0;
    int i;
    int c;
    char *p;

    struct termios t_new, t_old;

    memset(&oksigs, 0, sizeof(oksigs));

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = intr;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    for(i = 1; i < sizeof(sigs) / sizeof(sigs[0]); i++)
	if (i != SIGALRM)
	    if (sigaction(i, &sa, &sigs[i]) == 0)
		oksigs[i] = 1;

    if((tty = fopen("/dev/tty", "r")) != NULL)
	rk_cloexec_file(tty);
    else
	tty = stdin;

    fprintf(stderr, "%s%s", preprompt, prompt);
    fflush(stderr);

    if(echo == 0){
	tcgetattr(fileno(tty), &t_old);
	memcpy(&t_new, &t_old, sizeof(t_new));
	t_new.c_lflag &= ~ECHO;
	tcsetattr(fileno(tty), TCSANOW, &t_new);
    }
    intr_flag = 0;
    p = buf;
    while(intr_flag == 0){
	c = getc(tty);
	if(c == EOF){
	    if(!ferror(tty))
		ret = 1;
	    break;
	}
	if(c == '\n')
	    break;
	if(of == 0)
	    *p++ = c;
	of = (p == buf + len);
    }
    if(of)
	p--;
    *p = 0;

    if(echo == 0){
	fprintf(stderr, "\n");
	tcsetattr(fileno(tty), TCSANOW, &t_old);
    }

    if(tty != stdin)
	fclose(tty);

    for(i = 1; i < sizeof(sigs) / sizeof(sigs[0]); i++)
	if (oksigs[i])
	    sigaction(i, &sigs[i], NULL);

    if(ret)
	return -3;
    if(intr_flag)
	return -2;
    if(of)
	return -1;
    return 0;
}

#endif /* HAVE_CONIO_H */

int
_hx509_UI_UTIL_read_pw_string(char *buf, int length, const char *prompt, int verify)
{
    int ret;

    ret = read_string("", prompt, buf, length, 0);
    if (ret)
	return ret;

    if (verify & UI_UTIL_FLAG_VERIFY) {
	char *buf2;
	buf2 = malloc(length);
	if (buf2 == NULL)
	    return 1;

	ret = read_string("Verify password - ", prompt, buf2, length, 0);
	if (ret) {
	    free(buf2);
	    return ret;
	}
	if (strcmp(buf2, buf) != 0) {
	    if (!(verify & UI_UTIL_FLAG_VERIFY_SILENT)) {
		fprintf(stderr, "Verify failure\n");
		fflush(stderr);
	    }
	    ret = 1;
	}
	free(buf2);
    }
    return ret;
}

/* lib/hcrypto/ui.c code over */

/**
 * @page page_lock Locking and unlocking certificates and encrypted data.
 *
 * See the library functions here: @ref hx509_lock
 */

struct hx509_lock_data {
    struct _hx509_password password;
    hx509_certs certs;
    hx509_prompter_fct prompt;
    void *prompt_data;
};

static struct hx509_lock_data empty_lock_data = {
    { 0, NULL },
    NULL,
    NULL,
    NULL
};

hx509_lock _hx509_empty_lock = &empty_lock_data;

/*
 *
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_lock_init(hx509_context context, hx509_lock *lock)
{
    hx509_lock l;
    int ret;

    *lock = NULL;

    l = calloc(1, sizeof(*l));
    if (l == NULL)
	return ENOMEM;

    ret = hx509_certs_init(context,
			   "MEMORY:locks-internal",
			   0,
			   NULL,
			   &l->certs);
    if (ret) {
	free(l);
	return ret;
    }

    *lock = l;

    return 0;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_lock_add_password(hx509_lock lock, const char *password)
{
    void *d;
    char *s;

    s = strdup(password);
    if (s == NULL)
	return ENOMEM;

    d = realloc(lock->password.val,
		(lock->password.len + 1) * sizeof(lock->password.val[0]));
    if (d == NULL) {
	free(s);
	return ENOMEM;
    }
    lock->password.val = d;
    lock->password.val[lock->password.len] = s;
    lock->password.len++;

    return 0;
}

HX509_LIB_FUNCTION const struct _hx509_password * HX509_LIB_CALL
_hx509_lock_get_passwords(hx509_lock lock)
{
    return &lock->password;
}

HX509_LIB_FUNCTION hx509_certs HX509_LIB_CALL
_hx509_lock_unlock_certs(hx509_lock lock)
{
    return lock->certs;
}

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_lock_reset_passwords(hx509_lock lock)
{
    size_t i;
    for (i = 0; i < lock->password.len; i++)
	free(lock->password.val[i]);
    free(lock->password.val);
    lock->password.val = NULL;
    lock->password.len = 0;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_lock_add_cert(hx509_context context, hx509_lock lock, hx509_cert cert)
{
    return hx509_certs_add(context, lock->certs, cert);
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_lock_add_certs(hx509_context context, hx509_lock lock, hx509_certs certs)
{
    return hx509_certs_merge(context, lock->certs, certs);
}

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_lock_reset_certs(hx509_context context, hx509_lock lock)
{
    hx509_certs certs = lock->certs;
    int ret;

    ret = hx509_certs_init(context,
			   "MEMORY:locks-internal",
			   0,
			   NULL,
			   &lock->certs);
    if (ret == 0)
	hx509_certs_free(&certs);
    else
	lock->certs = certs;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
_hx509_lock_find_cert(hx509_lock lock, const hx509_query *q, hx509_cert *c)
{
    *c = NULL;
    return 0;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_lock_set_prompter(hx509_lock lock, hx509_prompter_fct prompt, void *data)
{
    lock->prompt = prompt;
    lock->prompt_data = data;
    return 0;
}

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_lock_reset_promper(hx509_lock lock)
{
    lock->prompt = NULL;
    lock->prompt_data = NULL;
}

static int
default_prompter(void *data, const hx509_prompt *prompter)
{
    if (hx509_prompt_hidden(prompter->type)) {
	if(_hx509_UI_UTIL_read_pw_string(prompter->reply.data,
                                         prompter->reply.length,
                                         prompter->prompt,
                                         0))
	    return 1;
    } else {
	char *s = prompter->reply.data;

	fputs (prompter->prompt, stdout);
	fflush (stdout);
	if(fgets(prompter->reply.data,
		 prompter->reply.length,
		 stdin) == NULL)
	    return 1;
	s[strcspn(s, "\n")] = '\0';
    }
    return 0;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_lock_prompt(hx509_lock lock, hx509_prompt *prompt)
{
    if (lock->prompt == NULL)
	return HX509_CRYPTO_NO_PROMPTER;
    return (*lock->prompt)(lock->prompt_data, prompt);
}

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_lock_free(hx509_lock lock)
{
    if (lock) {
	hx509_certs_free(&lock->certs);
	hx509_lock_reset_passwords(lock);
	memset(lock, 0, sizeof(*lock));
	free(lock);
    }
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_prompt_hidden(hx509_prompt_type type)
{
    /* default to hidden if unknown */

    switch (type) {
    case HX509_PROMPT_TYPE_QUESTION:
    case HX509_PROMPT_TYPE_INFO:
	return 0;
    default:
	return 1;
    }
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_lock_command_string(hx509_lock lock, const char *string)
{
    if (strncasecmp(string, "PASS:", 5) == 0) {
	hx509_lock_add_password(lock, string + 5);
    } else if (strcasecmp(string, "PROMPT") == 0) {
	hx509_lock_set_prompter(lock, default_prompter, NULL);
    } else
	return HX509_UNKNOWN_LOCK_COMMAND;
    return 0;
}
