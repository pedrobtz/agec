#include <ctype.h>
#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "bech32.h"
#include "crypto.h"
#include "util.h"

char *argv0;

typedef struct Keypair Keypair;
struct Keypair {
	uchar pub[32];
	uchar priv[32];
};

static void
usage(void)
{
	fprintf(stderr, "usage: %s\n", argv0);
	exit(1);
}

static void
dief(const char *fmt, ...)
{
	va_list l;

	va_start(l, fmt);
	fprintf(stderr, "%s: ", argv0);
	vfprintf(stderr, fmt, l);
	fprintf(stderr, "\n");
	va_end(l);
	exit(1);
}

static Keypair
genkey(void)
{
	Keypair kp;
	int ok;

	ok = randombuf(kp.priv, 32);
	if(!ok) 
		dief("failed to generate private key");
	ok = x25519pub(kp.pub, kp.priv);
	if(!ok) {
		dief("failed to generate public key: "
				"curve25519 low order point");
	}
	return kp;
}

static char *
upper(char *s)
{
	int i;

	for(i = 0; s[i]; i++)
		s[i] = toupper(s[i]);
	return s;
}

static void
print(Keypair kp)
{
	uchar pub[63];
	uchar priv[75];
	int ok, r;

	ok = bech32encode("age", kp.pub, 32, pub);
	if(!ok)
		dief("failed to encode key");
	ok = bech32encode("age-secret-key-", kp.priv, 32, priv);
	if(!ok)
		dief("failed to encode key");
	if(!isatty(1))
		fprintf(stderr, "Public key: %s\n", pub);
	r = printf("# public key: %s\n", pub);
	if(r < 0)
		dief("failed to write: %s", strerror(errno));
	r = puts(upper((char *)priv));
	if(r == EOF)
		dief("failed to write: %s", strerror(errno));
	explicit_bzero(priv, sizeof priv);
	return;
}

int
main(int argc, char *argv[])
{
	Keypair kp;

	argv0 = argv[0] ? basename(argv[0]) : "cage-keygen";
	if(argc != 1)
		usage();
	kp = genkey();
	print(kp);
	explicit_bzero(kp.priv, 32);
	return 0;
}
