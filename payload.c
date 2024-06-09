#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>

#include "common.h"
#include "base64.h"
#include "util.h"
#include "io.h"
#include "payload.h"

#define CHUNKLEN 64*1024
#define TAGLEN   16      /* poly1305 authentication tag */

static int eof(Ibuf *b);
static size_t ploutlen(void);
static void incnonce(uchar nonce[12]);
static size_t encchunk(EVP_AEAD_CTX *ctx, Data in, uchar nonce[12], uchar *out);
static size_t decchunk(EVP_AEAD_CTX *ctx, Data in, uchar nonce[12], uchar *out);

void
payloadkey(uchar filekey[16], uchar nonce[16], uchar plkey[32])
{
	static const uchar label[] = "payload";
	int ok;

	ok = HKDF(plkey, 32, EVP_sha256(), filekey, 16,
			nonce, 16, label, sizeof(label) - 1);
	if(!ok)
		errx(1, "failed to derive payload key: %s",
				ERR_error_string(ERR_get_error(), NULL));
}

const char *
plencrypt(Ibuf *in, Obuf *out, uchar plkey[32])
{
	uchar inbuf[CHUNKLEN], outbuf[CHUNKLEN + TAGLEN];
	uchar nonce[12] = {0};
	const char *e;
	EVP_AEAD_CTX *ctx;
	Data ichunk;
	size_t outlen;
	ssize_t nr, nw;
	int last;
	int ok;

	outlen = sizeof(outbuf);
	assert(sizeof(outbuf) == ploutlen());
	ichunk.data = inbuf;
	ctx = EVP_AEAD_CTX_new();
	if(ctx == NULL)
		return "failed to allocate a context";
	ok = EVP_AEAD_CTX_init(ctx, EVP_aead_chacha20_poly1305(),
			plkey, 32, TAGLEN, NULL);
	if(!ok) {
		e = ERR_error_string(ERR_get_error(), NULL);
		goto fail;
	}
	for(last = 0; !last; incnonce(nonce)) {
		nr = bread(in, inbuf, CHUNKLEN);
		if(nr == -1) {
			e = strerror(errno);
			goto fail;
		}
		last = eof(in);
		if(last == -1) {
			e = strerror(errno);
			goto fail;
		}
		ichunk.len = nr;
		if(last)
			nonce[11] = 1;
		outlen = encchunk(ctx, ichunk, nonce, outbuf);
		nw = bwrite(out, outbuf, outlen);
		if(nw == -1) {
			e = strerror(errno);
			goto fail;
		}
	}
	EVP_AEAD_CTX_free(ctx);
	return NULL;
fail:
	EVP_AEAD_CTX_free(ctx);
	return e;
}

static int
eof(Ibuf *b)
{
	ssize_t nr;
	char c;

	if(b->eof)
		return 1;
	nr = bpeek(b, &c);
	if(nr == -1)
		return -1;
	else if(nr == 0)
		return 1;
	else
		return 0;
}

static size_t
ploutlen(void)
{
	return CHUNKLEN + EVP_AEAD_max_overhead(EVP_aead_chacha20_poly1305());
}

static void
incnonce(uchar nonce[12])
{
	int i;

	for(i = 10; i > 0; i--) {
		nonce[i]++;
		if(nonce[i] != 0)
			break;
		if(i == 0)
			errx(1, "payload is too long; chunk counter wrapped");
	}
}

static size_t
encchunk(EVP_AEAD_CTX *ctx, Data in, uchar nonce[12], uchar *out)
{
	size_t outlen;
	int ok;

	ok = EVP_AEAD_CTX_seal(ctx, out, &outlen, CHUNKLEN + TAGLEN,
			nonce, 12, in.data, in.len, NULL, 0);
	if(!ok)
		errx(1, "%s", ERR_error_string(ERR_get_error(), NULL));
	return outlen;
}

const char *
pldecrypt(Ibuf *in, Obuf *out, uchar plkey[32])
{
	uchar outbuf[CHUNKLEN + TAGLEN], inbuf[CHUNKLEN + TAGLEN];
	uchar nonce[12] = {0};
	const char *e;
	EVP_AEAD_CTX *ctx;
	Data ichunk;
	size_t outlen;
	ssize_t nr, nw;
	int last;
	int ok;

	assert(sizeof(inbuf) == ploutlen());
	ichunk.data = inbuf;
	ctx = EVP_AEAD_CTX_new();
	if(ctx == NULL)
		return "failed to allocate a context";
	ok = EVP_AEAD_CTX_init(ctx, EVP_aead_chacha20_poly1305(),
			plkey, 32, TAGLEN, NULL);
	if(!ok) {
		e = ERR_error_string(ERR_get_error(), NULL);
		goto fail;
	}
	for(last = 0; !last; incnonce(nonce)) {
		nr = bread(in, inbuf, sizeof(inbuf));
		if(nr == -1) {
			e = strerror(errno);
			goto fail;
		}
		last = eof(in);
		if(last == -1) {
			e = strerror(errno);
			goto fail;
		}
		ichunk.len = nr;
		if(last)
			nonce[11] = 1;
		outlen = decchunk(ctx, ichunk, nonce, outbuf);
		nw = bwrite(out, outbuf, outlen);
		if(nw == -1) {
			e = strerror(errno);
			goto fail;
		}
	}
	EVP_AEAD_CTX_free(ctx);
	return NULL;
fail:
	EVP_AEAD_CTX_free(ctx);
	return e;
}

static size_t
decchunk(EVP_AEAD_CTX *ctx, Data in, uchar nonce[12], uchar *out)
{
	size_t outlen;
	int ok;

	ok = EVP_AEAD_CTX_open(ctx, out, &outlen, CHUNKLEN + TAGLEN,
			nonce, 12, in.data, in.len, NULL, 0);
	if(!ok)
		errx(1, "%s", ERR_error_string(ERR_get_error(), NULL));
	assert(outlen == in.len - TAGLEN);
	return outlen;
}

const char *
plinit(Ebuf *b, Ibuf *ib, uchar plkey[32])
{
	int ok;

	assert(sizeof(b->ibuf) == ploutlen());
	b->ctx = (struct Ectx *)EVP_AEAD_CTX_new();
	if(b->ctx == NULL)
		return "failed to allocate a context";
	ok = EVP_AEAD_CTX_init((EVP_AEAD_CTX *)b->ctx,
			EVP_aead_chacha20_poly1305(), plkey, 32, TAGLEN, NULL);
	if(!ok)
		return ERR_error_string(ERR_get_error(), NULL);
	b->in = ib;
	memset(b->nonce, 0, sizeof(b->nonce));
	b->cur = b->size = 0;
	return NULL;
}

void
plfree(Ebuf *b)
{
	EVP_AEAD_CTX_free((EVP_AEAD_CTX *)b->ctx);
	explicit_bzero(b, sizeof(*b));
}

ssize_t
plread(Ebuf *b, void *buf, size_t nbytes)
{
	Data ichunk;
	size_t orig = nbytes, c, rest;
	ssize_t nr;
	int last;

	ichunk.data = b->ibuf;
	while(nbytes > 0) {
		if(b->cur == b->size) {
			if(b->nonce[11] == 1)
				return 0;
			b->cur = b->size = 0;
		}
		if(b->size == 0) {
			last = eof(b->in);
			if(last == -1)
				return -1;
			if(last)
				b->nonce[11] = 1;
			nr = bread(b->in, b->ibuf, sizeof(b->ibuf));
			if(nr == -1)
				return -1;
			if(nr == 0)
				return 0;
			ichunk.len = nr;
			b->size = decchunk((EVP_AEAD_CTX *)b->ctx,
					ichunk, b->nonce, b->obuf);
			incnonce(b->nonce);
		}
		rest = b->size - b->cur;
		c = (rest > nbytes) ? nbytes : rest;
		memcpy(buf, b->obuf + b->cur, c);
		buf = (uchar *)buf + c;
		b->cur += c;
		nbytes -= c;
	}
	return orig - nbytes;
}

ssize_t
plpeek(Ebuf *b, char *c)
{
	Data ichunk;
	int last;
	ssize_t nr;

	ichunk.data = b->ibuf;
	if(b->cur < b->size) {
		*c = b->obuf[b->cur];
		return 1;
	}
	b->cur = b->size = 0;
	nr = bread(b->in, b->ibuf, sizeof(b->ibuf));
	if(nr == -1)
		return -1;
	if(nr == 0)
		return 0;
	last = eof(b->in);
	if(last == -1)
		return -1;
	if(last)
		b->nonce[11] = 1;
	ichunk.len = nr;
	b->size = decchunk((EVP_AEAD_CTX *)b->ctx, ichunk, b->nonce, b->obuf);
	incnonce(b->nonce);
	*c = b->obuf[0];
	return 1;
}
