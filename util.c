#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "common.h"
#include "util.h"

extern const char *argv0;
char ebuf[512];

const char *
ewrap(const char *outer, const char *inner)
{
	usize olen, ilen;

	olen = strlen(outer);
	ilen = strlen(inner);
	if(olen + 2 + ilen + 1 > sizeof(ebuf)) {
		if(olen + 2 + 1 > sizeof(ebuf)) {
			ilen = 0;
			olen = sizeof(ebuf) - 2 - 1;
		} else {
			ilen = sizeof(ebuf) - olen - 2 - 1;
		}
	}
	memmove(ebuf + olen + 2, inner, ilen);
	memcpy(ebuf, outer, olen);
	ebuf[olen] = ':';
	ebuf[olen + 1] = ' ';
	ebuf[olen + 2 + ilen] = '\0';
	return ebuf;
}

const char *
esys(const char *outer)
{
	return ewrap(outer, strerror(errno));
}

const char *
efmt(const char *fmt, ...)
{
	va_list l;

	va_start(l, fmt);
	(void)vsnprintf(ebuf, sizeof(ebuf), fmt, l);
	ebuf[sizeof(ebuf) - 1] = '\0';
	va_end(l);
	return ebuf;
}

void
die(const char *msg)
{
	fprintf(stderr, "%s: %s\n", argv0, msg);
	exit(1);
}

void *
reallocarr(void *p, usize nmemb, usize size)
{
	usize n;

	n = nmemb * size;
	if(nmemb > 0 && n / nmemb != size) {
		errno = EOVERFLOW;
		return NULL;
	}
	return realloc(p, n);
}

static const char *
readpass(int fd, char *buf, usize len)
{
	usize i;
	int nr, over;
	char c;

	over = (len == 0) ? 1 : 0;
	for(i = 0; ; i++) {
		if(!over && i >= len - 1)
			over = 1;
		nr = read(fd, &c, 1);
		if(nr == -1)
			return strerror(errno);
		if(nr == 0 || c == '\n' || c == '\r') {
			if(!over)
				buf[i] = '\0';
			break;
		}
		if(!over)
			buf[i] = c;
	}
	if(over)
		return efmt("passphrase is too long (max %u bytes)", len);
	(void)write(fd, "\n", 1);
	return NULL;
}

/* TODO: consider the need to mess with signals */
const char *
getpassword(const char *prompt, char *buf, usize len)
{
	struct termios term;
	const char *e = NULL;
	int fd, r;

	fd = open("/dev/tty", O_RDWR);
	if(fd == -1)
		return esys("failed to open /dev/tty");
	r = tcgetattr(fd, &term);
	if(r == -1) {
		e = strerror(errno);
		goto out;
	}
	term.c_lflag &= ~ECHO;
	r = tcsetattr(fd, TCSANOW, &term);
	if(r == -1) {
		e = esys("unable to turn off echo");
		goto out;
	}
	(void)write(fd, prompt, strlen(prompt));
	e = readpass(fd, buf, len);
	if(e)
		goto out;
	term.c_lflag |= ECHO;
	r = tcsetattr(fd, TCSANOW, &term);
	if(r == -1)
		e = esys("unable to turn on echo");
out:
	close(fd);
	return e;
}

void
wipe(void *buf, usize len)
{
	volatile char *p;

	p = (char *)buf;
	while(len--)
		*p++ = 0;
}

const char *
xprogname(const char *arg0, const char *def)
{
	const char *s, *last;

	if(arg0 == NULL || *arg0 == '\0')
		return def;
	for(s = arg0, last = NULL; *s; s++) {
		if(*s == '/')
			last = s;
	}
	if(last == NULL)
		return arg0;
	if(last == s - 1)
		return def;
	return last + 1;
}
