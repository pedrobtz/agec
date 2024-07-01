#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

extern char *argv0;
char ebuf[512];

const char *
ewrap(const char *outer, const char *inner)
{
	size_t olen, ilen;

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
reallocarr(void *p, size_t nmemb, size_t size)
{
	size_t n;

	n = nmemb * size;
	if(nmemb > 0 && n / nmemb != size) {
		errno = EOVERFLOW;
		return NULL;
	}
	return realloc(p, n);
}
