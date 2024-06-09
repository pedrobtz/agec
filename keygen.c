#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/curve25519.h>

#include "common.h"
#include "bech32.h"
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

static Keypair
genkey(void)
{
	Keypair kp;

	X25519_keypair(kp.pub, kp.priv);
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
	int ok;

	ok = bech32encode("age", kp.pub, 32, pub);
	if(!ok)
		goto fail;
	ok = bech32encode("age-secret-key-", kp.priv, 32, priv);
	if(!ok)
		goto fail;
	if(!isatty(1))
		fprintf(stderr, "Public key: %s\n", pub);
	printf("# public key: %s\n", pub);
	puts(upper((char *)priv));
	explicit_bzero(priv, sizeof priv);
	return;
fail:
	fprintf(stderr, "failed to encode key");
	exit(1);
}

int
main(int argc, char *argv[])
{
	Keypair kp;

	argv0 = argv[0] ? argv[0] : "cage-keygen";
	if(argc != 1)
		usage();
	kp = genkey();
	print(kp);
	explicit_bzero(kp.priv, 32);
	return 0;
}
