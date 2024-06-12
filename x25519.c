#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>

#include "common.h"
#include "base64.h"
#include "bech32.h"
#include "header.h"
#include "keyenc.h"
#include "util.h"
#include "crypto.h"
#include "x25519.h"

#define HDRINITLEN  128
#define BECHPUBLEN  62
#define BECHPRIVLEN 74
#define TAGLEN      16      /* poly1305 authentication tag */

static void wrap(uchar out[32], uchar share[32], uchar secret[32], uchar pubkey[32]);
static Data body(uchar share[32], uchar esecret[32], uchar pubkey[32], Data filekey);

void
x25519stanza(Header *h, Data filekey, uchar pubkey[32])
{
	uchar esecret[32], share[32];
	uchar b64share[B64EBUFLEN(sizeof(share))], *b64body;
	Data b;
	size_t outlen;
	int ok;

	ok = RAND_bytes(esecret, sizeof esecret);
	if(!ok)
		errx(1, "x25519: failed to generate ephemeral secret");
	ok = x25519(share, esecret, curve25519basepoint);
	if(!ok)
		errx(1, "x25519: internal failure");
	base64encode(share, b64share, sizeof share, &outlen, 0);
	hdrappend(h, "-> X25519 %s\n", b64share);
	b = body(share, esecret, pubkey, filekey);
	b64body = emalloc(B64EBUFLEN(b.len));
	base64encode(b.data, b64body, b.len, &outlen, 0);
	hdrappend(h, "%s\n", b64body);
	free(b64body);
	free(b.data);
	explicit_bzero(esecret, sizeof esecret);
}

static Data
body(uchar share[32], uchar esecret[32], uchar pubkey[32], Data filekey)
{
	uchar secret[32], wrapkey[32];
	Data body;
	int ok;

	ok = x25519(secret, esecret, pubkey);
	if(!ok)
		errx(1, "x25519: internal failure");
	wrap(wrapkey, share, secret, pubkey);
	body = keyenc(wrapkey, filekey);
	explicit_bzero(secret, sizeof secret);
	return body;
}

static void
wrap(uchar out[32], uchar share[32], uchar secret[32], uchar pubkey[32])
{
	static const uchar info[] = "age-encryption.org/v1/X25519";
	uchar salt[64];
	int ok;

	memcpy(salt, share, 32);
	memcpy(salt + 32, pubkey, 32);
	ok = HKDF(out, 32, EVP_sha256(), secret, 32, salt, sizeof(salt),
			info, sizeof(info) - 1);
	if(!ok) {
		explicit_bzero(share, 32);
		explicit_bzero(secret, 32);
		errx(1, "x25519: failed to derive key");
	}
}

int
x25519pubkey(char *bech, uchar pubkey[32])
{
	uchar data[BECHPUBLEN - 8];
	size_t datalen, hrplen;
	int ok;

	if(strlen(bech) != BECHPUBLEN)
		return 0;
	ok = bech32decode(bech, data, &datalen, &hrplen);
	if(!ok)
		return 0;
	if(datalen != 32)
		return 0;
	memcpy(pubkey, data, 32);
	return 1;
}

int
x25519privkey(char bech[74+1], uchar privkey[32])
{
	static const char goodprefix[] = "AGE-SECRET-KEY-1";
	uchar data[BECHPRIVLEN - 8];
	size_t datalen, hrplen;
	int ok;

	if(strnlen(bech, BECHPRIVLEN) != BECHPRIVLEN)
		return 0;
	bech[74] = '\0';
	if(memcmp(bech, goodprefix, sizeof(goodprefix) - 1) != 0)
		return 0;
	ok = bech32decode(bech, data, &datalen, &hrplen);
	if(!ok)
		return 0;
	if(datalen != 32)
		return 0;
	memcpy(privkey, data, 32);
	return 1;
}

int
x25519getkey(uchar k[16], X25519arg *arg, uchar privkey[32])
{
	uchar secret[32], pubkey[32], wrapkey[32];
	int ok;

	ok = x25519(secret, privkey, arg->share);
	if(!ok)
		errx(1, "x25519: failed to compute");
	ok = x25519pub(pubkey, privkey);
	if(!ok)
		errx(1, "x25519: internal failure");
	wrap(wrapkey, arg->share, secret, pubkey);
	return keydec(wrapkey, arg->body, k);
}
