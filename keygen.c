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

#define BADFORMAT -2

char *argv0;

typedef struct Keypair Keypair;
struct Keypair {
	uchar pub[32];
	uchar priv[32];
};

typedef struct Input Input;
struct Input {
	size_t size, cur;
	uchar buf[8192];
};

typedef struct Output Output;
struct Output {
	size_t cur;
	uchar buf[8192];
};

static void
ininit(Input *b)
{
	b->size = b->cur = 0;
}

static void
outinit(Output *b)
{
	b->cur = 0;
}

static int
bgetc(Input *b, char *c)
{
	ssize_t nr;

	if(b->cur == b->size)
		b->cur = b->size = 0;
	if(b->size == 0) {
		nr = read(0, b->buf, sizeof(b->buf));
		if(nr == -1)
			return -1;
		if(nr == 0)
			return 0;
		b->size = nr;
	}
	*c = b->buf[b->cur];
	b->cur++;
	return 1;
}

static ssize_t
writeall(int fd, const void *buf, size_t nbytes)
{
	size_t off;
	ssize_t nw;

	for(off = 0; off < nbytes; off += nw) {
		nw = write(fd, (char *)buf + off, nbytes - off);
		if(nw <= 0)
			return -1;
	}
	return nbytes;
}

static ssize_t
bflush(Output *b)
{
	ssize_t r;

	if(b->cur == 0)
		return 0;
	r = writeall(1, b->buf, b->cur);
	b->cur = 0;
	return r;
}

static ssize_t
bwrite(Output *b, void *buf, size_t nbytes)
{
        size_t rest, c;
        ssize_t ret;

	if(nbytes > sizeof(b->buf)) {
		ret = bflush(b);
		if(ret == -1)
			return -1;
		return writeall(1, buf, nbytes);
	}
	rest = sizeof(b->buf) - b->cur;
	c = (rest > nbytes) ? nbytes : rest;
	memcpy(b->buf + b->cur, buf, c);
	if(rest > nbytes) {
		b->cur += nbytes;
		return 0;
        } else {
		ret = writeall(1, b->buf, b->cur);
		if(ret == -1)
			return -1;
		memcpy(b->buf, (uchar *)buf + rest, nbytes - rest);
		b->cur = nbytes - rest;
		return ret;
        }
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-y]\n", argv0);
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
	wipe(pub, sizeof pub);
	wipe(priv, sizeof priv);
	return;
}

static ssize_t
skipline(Input *b)
{
	ssize_t nr;
	char c;

	for(;;) {
		nr = bgetc(b, &c);
		if(nr <= 0)
			return nr;
		if(c == '\n')
			return 1;
	}
}

static int
parsekey(char bech[74 + 1], uchar out[32])
{
	static const char goodprefix[] = "AGE-SECRET-KEY-1";
	uchar data[74 - 8];
	size_t datalen, hrplen;
	int ok;

	bech[74] = 0;
	if(memcmp(bech, goodprefix, sizeof(goodprefix) - 1) != 0)
		return 0;
	ok = bech32decode(bech, data, &datalen, &hrplen);
	if(!ok)
		return BADFORMAT;
	if(datalen != 32)
		return BADFORMAT;
	memcpy(out, data, 32);
	return 1;
}

static int
readkey(Input *in, char first, uchar out[32])
{
	char bech[74 + 1];
	ssize_t nr;
	int i;
	char c;

	bech[0] = first;
	for(i = 0; i < 73; i++) {
		nr = bgetc(in, &c);
		if(nr == -1)
			return -1;
		if(nr == 0 || c == '\0')
			return BADFORMAT;
		bech[i + 1] = c;
	}
	nr = bgetc(in, &c);
	if(nr == -1)
		return -1;
	if(nr == 0 || c != '\n')
		return BADFORMAT;
	return parsekey(bech, out);
}

static const char *
writepub(Output *out, uchar priv[32])
{
	uchar pub[32], bech[63];
	ssize_t nr;
	int ok;

	ok = x25519pub(pub, priv);
	if(!ok) {
		return "failed to generate public key: "
					"curve25519 low order point";
	}
	ok = bech32encode("age", pub, 32, bech);
	if(!ok)
		return "failed to encode key";
	nr = bwrite(out, bech, sizeof(bech));
	if(nr == -1)
		return esys("failed to write");
	nr = bwrite(out, "\n", 1);
	if(nr == -1)
		return esys("failed to write");
	wipe(bech, sizeof(bech));
	wipe(pub, sizeof(pub));
	return NULL;
}

static void
filekeys(void)
{
	Input in;
	Output out;
	uchar priv[32];
	const char *e = NULL;
	ssize_t nr;
	int lineno;
	char c;

	ininit(&in);
	outinit(&out);
	for(lineno = 1; ; lineno++) {
		nr = bgetc(&in, &c);
		if(nr == -1) {
			e = esys("failed to read");
			goto out;
		}
		if(nr == 0)
			goto out;
		if(c == '#') {
			nr = skipline(&in);
			if(nr == -1) {
				e = esys("failed to read");
				goto out;
			}
			if(nr == 0)
				return;
			continue;
		} else if(c == '\n') {
			continue;
		}
		nr = readkey(&in, c, priv);
		if(nr == -1) {
			e = esys("failed to read");
			goto out;
		}
		if(nr == -2) {
			e = efmt("invalid private key at line %d", lineno);
			goto out;
		}
		e = writepub(&out, priv);
		if(e)
			goto out;
	}
out:
	bflush(&out);
	wipe(&in, sizeof(in));
	wipe(&out, sizeof(out));
	if(e)
		dief("%s", e);
}

int
main(int argc, char *argv[])
{
	Keypair kp;

	argv0 = argv[0] ? basename(argv[0]) : "agec-keygen";
	if(argc == 1) {
		kp = genkey();
		print(kp);
		wipe(&kp, sizeof(kp));
	} else if(argc == 2 && strcmp(argv[1], "-y") == 0) {
		filekeys();
	} else {
		usage();
	}
	return 0;
}
