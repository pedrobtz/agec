#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "crypto.h"
#include "util.h"
#include "keyenc.h"

void
keyenc(uchar key[32], uchar filekey[16], uchar out[32])
{
	Chacha20poly1305ctx ctx;
	static const uchar nonce[12] = {0};

	chacha20poly1305init(&ctx, key, nonce);
	chacha20poly1305write(&ctx, out, NULL, 0, filekey, 16);
	explicit_bzero(&ctx, sizeof(ctx));
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
