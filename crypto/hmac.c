#include <stdint.h>
#include <string.h>

#include "../common.h"
#include "../crypto.h"

static void
hashcat(Sha256ctx *s, const uchar pad[64], const uchar *in, size_t inlen, uchar out[32])
{
	sha256init(s);
	sha256update(s, pad, 64);
	sha256update(s, in, inlen);
	sha256final(s, out);
}

void
hmacsha256(const uchar *k, size_t klen, const uchar *in, size_t inlen, uchar out[32])
{
	Sha256ctx ctx;
	uchar pad[64], kh[32], h[32];
	size_t i;

	if(klen > 64) {
		sha256init(&ctx);
		sha256update(&ctx, k, klen);
		sha256final(&ctx, kh);
		k = kh;
		klen = 32;
	}
	memset(pad, 0x36, 64);
	for(i = 0; i < klen; i++)
		pad[i] ^= k[i];
	hashcat(&ctx, pad, in, inlen, h);
	memset(pad, 0x5c, 64);
	for(i = 0; i < klen; i++)
		pad[i] ^= k[i];
	hashcat(&ctx, pad, h, 32, out);
	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(pad, sizeof(pad));
	explicit_bzero(kh, sizeof(kh));
	explicit_bzero(h, sizeof(h));
}
