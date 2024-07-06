#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "crypto.h"
#include "base64.h"
#include "util.h"
#include "header.h"

#define HDRINITLEN 128

static const uchar label[] = "header";

const char *
hdrinit(Header *h)
{
	h->data = malloc(HDRINITLEN);
	if(h->data == NULL)
		return strerror(errno);
	h->allocated = HDRINITLEN;
	h->len = 0;
	return NULL;
}

const char *
hdrappend(Header *h, char *fmt, ...)
{
	va_list l;
	char buf[256];
	int ret;
	
	va_start(l, fmt);
	ret = vsnprintf(buf, sizeof buf, fmt, l);
	if(ret < 0 || (size_t)ret >= sizeof buf)
		return "buffer overflow";
	if(h->len + ret >= h->allocated) {
		h->allocated = h->len + ret + 1;
		h->data = realloc(h->data, h->allocated);
		if(h->data == NULL)
			return esys("");
	}
	memcpy(h->data + h->len, buf, ret);
	h->len += ret;
	va_end(l);
	return NULL;
}

/* out length must be at least B64EBUFLEN(32) */
void
hdrmac(uchar *data, size_t len, uchar filekey[16], char *out, size_t *outlen)
{
	uchar md[32];

	mac(data, len, filekey, md);
	base64encode(md, (uchar *)out, sizeof md, outlen, 0);
}

void
mac(uchar *data, size_t len, uchar filekey[16], uchar out[32])
{
	uchar dk[32];

	hkdfsha256(filekey, 16, NULL, 0, label, sizeof(label) - 1, dk);
	hmacsha256(dk, sizeof(dk), data, len, out);
}
