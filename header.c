#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>

#include "common.h"
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
	HMAC_CTX *ctx;
	unsigned int mdlen;
	int ok;

	ok = HKDF(dk, sizeof dk, EVP_sha256(), filekey.data, filekey.len,
		(uchar *)"", 0, label, sizeof(label) - 1);
	if(!ok)
		errx(1, "%s", ERR_error_string(ERR_get_error(), NULL));
	ctx = HMAC_CTX_new();
	if(!ctx)
		errx(1, "hmac: failed to create context");
	ok = HMAC_Init_ex(ctx, dk, sizeof dk, EVP_sha256(), NULL);
	if(!ok)
		errx(1, "hmac: failed to initialise context");
	assert(HMAC_size(ctx) == 32);
	ok = HMAC_Update(ctx, data, len);
	if(!ok)
		errx(1, "hmac: failed to compute digest");
	ok = HMAC_Final(ctx, out, &mdlen);
	if(!ok)
		errx(1, "hmac: failed to compute digest");
	assert(mdlen == 32);
	HMAC_CTX_free(ctx);
}
