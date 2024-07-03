#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "common.h"
#include "base64.h"
#include "crypto.h"
#include "util.h"
#include "io.h"
#include "payload.h"

#define CHUNKLEN 64*1024
#define TAGLEN   16      /* poly1305 authentication tag */

static int eof(Ibuf *b);
static const char *incnonce(uchar nonce[12]);
static size_t encchunk(Data in, uchar key[32], uchar nonce[12], uchar *out);
static size_t decchunk(Data in, uchar key[32], uchar nonce[12], uchar *out);

void
payloadkey(uchar filekey[16], uchar nonce[16], uchar plkey[32])
{
	static const uchar label[] = "payload";

	hkdfsha256(filekey, 16, nonce, 16, label, sizeof(label) - 1, plkey);
}

const char *
plencrypt(Ibuf *in, Obuf *out, uchar plkey[32])
{
	uchar inbuf[CHUNKLEN], outbuf[CHUNKLEN + TAGLEN];
	uchar nonce[12] = {0};
	Data ichunk;
	const char *e = NULL;
	size_t outlen;
	ssize_t nr, nw;
	int last;

	outlen = sizeof(outbuf);
	ichunk.data = inbuf;
	for(last = 0; !last; e = incnonce(nonce)) {
		if(e)
			return e;
		nr = bread(in, inbuf, CHUNKLEN);
		if(nr == -1)
			return ioerror(errno);
		last = eof(in);
		if(last == -1)
			return ioerror(errno);
		ichunk.len = nr;
		if(last)
			nonce[11] = 1;
		outlen = encchunk(ichunk, plkey, nonce, outbuf);
		nw = bwrite(out, outbuf, outlen);
		if(nw == -1)
			return strerror(errno);
	}
	return NULL;
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

static const char *
incnonce(uchar nonce[12])
{
	int i;

	for(i = 10; i > 0; i--) {
		nonce[i]++;
		if(nonce[i] != 0)
			break;
		if(i == 0)
			return "payload is too long; chunk counter wrapped";
	}
	return NULL;
}

static size_t
encchunk(Data in, uchar key[32], uchar nonce[12], uchar *out)
{
	Chacha20poly1305ctx ctx;

	chacha20poly1305init(&ctx, key, nonce);
	chacha20poly1305write(&ctx, out, NULL, 0, in.data, in.len);
	explicit_bzero(&ctx, sizeof(ctx));
	return in.len + TAGLEN;
}

const char *
pldecrypt(Ibuf *in, Obuf *out, uchar plkey[32])
{
	uchar outbuf[CHUNKLEN + TAGLEN], inbuf[CHUNKLEN + TAGLEN];
	uchar nonce[12] = {0};
	Data ichunk;
	const char *e = NULL;
	size_t outlen;
	ssize_t nr, nw;
	int last, i;

	ichunk.data = inbuf;
	for(last = 0, i = 0; !last; e = incnonce(nonce), i++) {
		if(e)
			return e;
		nr = bread(in, inbuf, sizeof(inbuf));
		if(nr == -1)
			return ioerror(errno);
		last = eof(in);
		if(last == -1)
			return ioerror(errno);
		if(last && i > 0 && nr == TAGLEN)
			return ioerror(EEMPTYCHUNK);
		ichunk.len = nr;
		if(last)
			nonce[11] = 1;
		outlen = decchunk(ichunk, plkey, nonce, outbuf);
		if(outlen == ~(size_t)0)
			return ioerror(errno);
		nw = bwrite(out, outbuf, outlen);
		if(nw == -1)
			return strerror(errno);
	}
	return NULL;
}

static size_t
decchunk(Data in, uchar key[32], uchar nonce[12], uchar *out)
{
	Chacha20poly1305ctx ctx;
	int fail;

	chacha20poly1305init(&ctx, key, nonce);
	fail = chacha20poly1305read(&ctx, out, NULL, 0, in.data, in.len);
	if(fail) {
		errno = EDECRYPT;
		return ~(size_t)0;
	}
	explicit_bzero(&ctx, sizeof(ctx));
	return in.len - TAGLEN;
}

const char *
plinit(Ebuf *b, Ibuf *ib, uchar plkey[32])
{
	b->in = ib;
	memcpy(b->key, plkey, 32);
	memset(b->nonce, 0, sizeof(b->nonce));
	b->cur = b->size = b->nchunk = 0;
	return NULL;
}

void
plfree(Ebuf *b)
{
	explicit_bzero(b, sizeof(*b));
}

ssize_t
plread(Ebuf *b, void *buf, size_t nbytes)
{
	Data ichunk;
	const char *e;
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
			if(last && b->nchunk > 0 && nr == TAGLEN) {
				errno = EEMPTYCHUNK;
				return -1;
			}
			if(nr == -1)
				return -1;
			if(nr == 0)
				return 0;
			b->nchunk++;
			ichunk.len = nr;
			b->size = decchunk(ichunk, b->key, b->nonce, b->obuf);
			if(b->size == ~(size_t)0)
				return -1;
			e = incnonce(b->nonce);
			if(e) {
				errno = EOVERFLOW;
				return -1;
			}
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
	const char *e;
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
	b->size = decchunk(ichunk, b->key, b->nonce, b->obuf);
	if(b->size == 0)
		return -1;
	e = incnonce(b->nonce);
	if(e) {
		errno = EOVERFLOW;
		return -1;
	}
	*c = b->obuf[0];
	return 1;
}
