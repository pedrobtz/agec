#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "crypto.h"
#include "util.h"
#include "keyenc.h"

#define TAGLEN      16      /* poly1305 authentication tag */

/* TODO: use static buffers */
Data
keyenc(uchar key[32], Data in)
{
	Data out;
	Chacha20poly1305ctx ctx;
	static const uchar nonce[12] = {0};

	chacha20poly1305init(&ctx, key, nonce);
	out.len = in.len + TAGLEN;
	out.data = emalloc(out.len);
	chacha20poly1305write(&ctx, out.data, NULL, 0, in.data, in.len);
	explicit_bzero(&ctx, sizeof(ctx));
	return out;
}

int
keydec(uchar key[32], uchar in[32], uchar out[16])
{
	static const uchar nonce[12] = {0};
	Chacha20poly1305ctx ctx;
	int fail;

	chacha20poly1305init(&ctx, key, nonce);
	fail = chacha20poly1305read(&ctx, out, NULL, 0, in, 32);
	explicit_bzero(&ctx, sizeof(ctx));
	return !fail;
}
