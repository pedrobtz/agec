#include <stdint.h>
#include <string.h>

#include "../common.h"
#include "../crypto.h"

void
hmacsha256(const uchar *k, size_t klen, const uchar *in, size_t inlen, uchar out[32])
{
	Hmacsha256ctx ctx;

	hmacsha256init(&ctx, k, klen);
	hmacsha256update(&ctx, in, inlen);
	hmacsha256final(&ctx, out);
	explicit_bzero(&ctx, sizeof(ctx));
}

void
hmacsha256init(Hmacsha256ctx *ctx, const uchar *k, size_t klen)
{
	uchar pad[64], kh[32];
	size_t i;

	if(klen > 64) {
		sha256init(&ctx->inner);
		sha256update(&ctx->inner, k, klen);
		sha256final(&ctx->inner, kh);
		k = kh;
		klen = 32;
	}
	sha256init(&ctx->inner);
	sha256init(&ctx->outer);
	memset(pad, 0x36, 64);
	for(i = 0; i < klen; i++)
		pad[i] ^= k[i];
	sha256update(&ctx->inner, pad, 64);
	memset(pad, 0x5c, 64);
	for(i = 0; i < klen; i++)
		pad[i] ^= k[i];
	sha256update(&ctx->outer, pad, 64);
	explicit_bzero(pad, sizeof(pad));
	explicit_bzero(kh, sizeof(kh));
}

void
hmacsha256update(Hmacsha256ctx *ctx, const uchar *in, size_t inlen)
{
	sha256update(&ctx->inner, in, inlen);
}

void
hmacsha256final(Hmacsha256ctx *ctx, uchar out[32])
{
	uchar h[32];

	sha256final(&ctx->inner, h);
	sha256update(&ctx->outer, h, 32);
	sha256final(&ctx->outer, out);
	explicit_bzero(h, sizeof(h));
}
