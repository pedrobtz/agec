#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "common.h"
#include "crypto.h"
#include "base64.h"
#include "header.h"
#include "keyenc.h"
#include "scrypt.h"
#include "util.h"

#define SALTLEN		16
#define COST		18	/* power of two of actual cost */

static const char label[] = "age-encryption.org/v1/scrypt";

static void catlabel(uchar *s);
static void stanza(Header *h, uchar filekey[16], char *pass, uchar *salt);
static void wrapkey(uchar key[32], char *pass, uchar *salt, unsigned factor);

void
scryptstanza(Header *h, uchar filekey[16], char *pass)
{
	uchar salt[SALTLEN + sizeof(label) - 1];

	if(randombuf(salt, SALTLEN) == 0)
		errx(1, "scrypt: failed to generate salt");
	stanza(h, filekey, pass, salt);
}

static void
stanza(Header *h, uchar filekey[16], char *pass, uchar *salt)
{
	uchar b64salt[B64EBUFLEN(SALTLEN)];
	uchar key[32];
	uchar body[32], b64body[B64EBUFLEN(32)];
	size_t outlen;

	base64encode(salt, b64salt, SALTLEN, &outlen, 0);
	catlabel(salt);
	wrapkey(key, pass, salt, COST);
	keyenc(key, filekey, body);
	base64encode(body, b64body, 32, &outlen, 0);
	hdrappend(h, "-> scrypt %s %d\n", b64salt, COST);
	hdrappend(h, "%s\n", b64body);
}

static void
wrapkey(uchar key[32], char *pass, uchar *salt, unsigned factor)
{
	const char *e;

	e = scrypt((uchar *)pass, strlen(pass),
			salt, SALTLEN + sizeof(label) - 1,
			1<<factor, 8, 1, key, 32);
	if(e)
		errx(1, "scrypt: %s", e);
		
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
