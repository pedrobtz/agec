#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "crypto.h"
#include "base64.h"
#include "header.h"

#define HDRINITLEN 128

static const uchar label[] = "header";

void
hdrinit(Header *h)
{
	h->data = emalloc(HDRINITLEN);
	h->allocated = HDRINITLEN;
	h->len = 0;
}

void
hdrappend(Header *h, char *fmt, ...)
{
	va_list l;
	char buf[256];
	int ret;
	
	va_start(l, fmt);
	ret = vsnprintf(buf, sizeof buf, fmt, l);
	if(ret < 0 || (size_t)ret >= sizeof buf)
		errx(1, "failed to generate header");
	if(h->len + ret >= h->allocated) {
		h->allocated = h->len + ret + 1;
		h->data = erealloc(h->data, h->allocated);
	}
	memcpy(h->data + h->len, buf, ret);
	h->len += ret;
	va_end(l);
}

/* out length must be at least B64EBUFLEN(32) */
void
hdrmac(uchar *data, size_t len, Data filekey, char *out, size_t *outlen)
{
	uchar md[32];

	mac(data, len, filekey, md);
	base64encode(md, (uchar *)out, sizeof md, outlen, 0);
}

void
mac(uchar *data, size_t len, Data filekey, uchar out[32])
{
	uchar dk[32];

	hkdfsha256(filekey.data, filekey.len, NULL, 0,
			label, sizeof(label) - 1, dk);
	hmacsha256(dk, sizeof(dk), data, len, out);
}
