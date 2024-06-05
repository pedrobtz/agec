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
	uchar *pub, *priv;
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

	kp.pub = emalloc(X25519_KEY_LENGTH);
	kp.priv = emalloc(X25519_KEY_LENGTH);
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

	ok = bech32encode("age", kp.pub, X25519_KEY_LENGTH, pub);
	if(!ok)
		goto fail;
	ok = bech32encode("age-secret-key-", kp.priv, X25519_KEY_LENGTH, priv);
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
	explicit_bzero(kp.priv, X25519_KEY_LENGTH);
	free(kp.pub);
	free(kp.priv);
	return 0;
}
