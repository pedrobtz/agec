#include <err.h>
#include <stdint.h>
#include <openssl/evp.h>

#include "common.h"
#include "util.h"
#include "keyenc.h"

#define TAGLEN      16      /* poly1305 authentication tag */

/* TODO: use static buffers */
Data
keyenc(uchar key[32], Data in)
{
	Data out;
	EVP_AEAD_CTX *ctx;
	const EVP_AEAD *aead;
	static const uchar nonce[12] = {0};
	size_t maxoutlen;
	int ok;

	aead = EVP_aead_chacha20_poly1305();
	ctx = EVP_AEAD_CTX_new();
	if(ctx == NULL)
		err(1, "failed to allocate a context");
	ok = EVP_AEAD_CTX_init(ctx, aead, key, 32, TAGLEN, NULL);
	if(!ok)
		errx(1, "failed to initialize context");
	maxoutlen = in.len + EVP_AEAD_max_overhead(aead);
	out.data = emalloc(maxoutlen);
	ok = EVP_AEAD_CTX_seal(ctx, out.data, &out.len, maxoutlen,
			nonce, sizeof nonce, in.data, in.len, NULL, 0);
	if(!ok)
		errx(1, "EVP failed");
        EVP_AEAD_CTX_cleanup(ctx);
	EVP_AEAD_CTX_free(ctx);
	return out;
}

int
keydec(uchar key[32], uchar in[32], uchar out[16])
{
	EVP_AEAD_CTX *ctx;
	const EVP_AEAD *aead;
	static const uchar nonce[12] = {0};
	size_t outlen;
	int ok;

	aead = EVP_aead_chacha20_poly1305();
	ctx = EVP_AEAD_CTX_new();
	if(ctx == NULL)
		err(1, "failed to allocate a context");
	ok = EVP_AEAD_CTX_init(ctx, aead, key, 32, TAGLEN, NULL);
	if(!ok)
		errx(1, "failed to initialize context");
	ok = EVP_AEAD_CTX_open(ctx, out, &outlen, 16,
			nonce, sizeof(nonce), in, 32, NULL, 0);
	if(ok && outlen != 16) /* somehow */
		errx(1, "failed to decrypt key: invalid output length");
	EVP_AEAD_CTX_cleanup(ctx);
	EVP_AEAD_CTX_free(ctx);
	return ok;
}
