#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "libscrypt/scrypt-kdf.h"
#include "common.h"
#include "base64.h"
#include "header.h"
#include "keyenc.h"
#include "scrypt.h"
#include "util.h"

#define SALTLEN		16
#define COST		18	/* power of two of actual cost */

static const char label[] = "age-encryption.org/v1/scrypt";

static void catlabel(uchar *s);
static void stanza(Header *h, Data filekey, char *pass, uchar *salt);
static void wrapkey(uchar key[32], char *pass, uchar *salt, unsigned factor);

void
scryptstanza(Header *h, Data filekey, char *pass)
{
	uchar salt[SALTLEN + sizeof(label) - 1];

	if(RAND_bytes(salt, SALTLEN) != 1)
		errx(1, "scrypt: failed to generate salt");
	stanza(h, filekey, pass, salt);
}

static void
stanza(Header *h, Data filekey, char *pass, uchar *salt)
{
	uchar b64salt[B64EBUFLEN(SALTLEN)], *b64body;
	uchar key[32];
	Data body;
	size_t outlen;

	base64encode(salt, b64salt, SALTLEN, &outlen, 0);
	catlabel(salt);
	wrapkey(key, pass, salt, COST);
	body = keyenc(key, filekey);
	b64body = emalloc(B64EBUFLEN(body.len));
	base64encode(body.data, b64body, body.len, &outlen, 0);
	if(b64body == NULL)
		err(1, "scrypt: failed to convert to base64");
	hdrappend(h, "-> scrypt %s %d\n", b64salt, COST);
	hdrappend(h, "%s\n", b64body);
	free(body.data);
	free(b64body);
}

static void
wrapkey(uchar key[32], char *pass, uchar *salt, unsigned factor)
{
	scrypt_kdf((uchar *)pass, strlen(pass),
			salt, SALTLEN + sizeof(label) - 1,
			1<<factor, 8, 1, key, 32);
}

static void
catlabel(uchar *s)
{
	char salt[SALTLEN];

	memcpy(salt, s, SALTLEN);
	memcpy(s, label, sizeof(label) - 1);
	memcpy(s + sizeof(label) - 1, salt, SALTLEN);
}

int
scryptgetkey(uchar k[16], Scryptarg *arg, char *pass)
{
	uchar salt[SALTLEN + sizeof(label) - 1];
	uchar wk[32];
	int ok;

	memcpy(salt, arg->salt, SALTLEN);
	catlabel(salt);
	wrapkey(wk, pass, salt, arg->cost);
	ok = keydec(wk, arg->body, k);
	if(!ok)
		return 0;
	return 1;
}
