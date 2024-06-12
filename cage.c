#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "crypto.h"
#include "base64.h"
#include "header.h"
#include "scrypt.h"
#include "x25519.h"
#include "io.h"
#include "parse.h"
#include "payload.h"

#define SCRYPTMAXCOST 22

struct Key {
	uchar r[32];
};
typedef struct Key Key;

struct Keys {
	Key *buf;
	size_t len;
	size_t capacity;
};
typedef struct Keys Keys;

static Data mkfilekey(void);
static void usage(void);
static void payload(uchar filekey[16], Ibuf *in, Obuf *out);
static void passenc(Header *h, Data filekey);
static void pubenc(Header *h, Data filekey, Keys *recs);
static void keyinit(Keys *keys);
static void keyfree(Keys *keys);
static void keynew(Keys *keys);
static void recadd(Keys *recs, char *bech);
static int privadd(Keys *recs, char bech[74+1]);
static ssize_t skipline(void *b, int encrypted);
static ssize_t getkey(void *b, Keys *privs, int encrypted);
static int checkencrypted(Ibuf *ib, Ebuf *eb);
static void matchscrypt(Ibuf *ib, Stanza *s);
static void readprivkeys(Keys *privs, const char *path);
static void encipher(Ibuf *in, Obuf *out, int ispass, Keys *recs);
static const char *validmac(Ibuf *in, uchar filekey[16], int *isvalid);
static void validatemac(Ibuf *in, uchar filekey[16]);
static void scryptkey(uchar filekey[16], Stanza *s);
static void match(Ibuf *in, uchar filekey[16], Stanza *s, Keys *ids, int *found);
static void decipher(Ibuf *in, Obuf *out, Keys *ids);

char *argv0;
static const char armorfirst[] = "-----BEGIN AGE ENCRYPTED FILE-----\n";
static const char armorlast[]  = "-----END AGE ENCRYPTED FILE-----\n";

static void
usage(void)
{
	fprintf(stderr, "usage:"
			"\t%s [-a] (-r recipient)...) [file]\n"
			"\t%s [-a] -p [file]\n"
			"\t%s [-i path] -d [file]\n",
			argv0, argv0, argv0);
	exit(1);
}

static void
keyinit(Keys *keys)
{
	keys->len = 0;
	keys->capacity = 32;
	keys->buf = emalloc(keys->capacity * sizeof(Key));
}

static void
keyfree(Keys *keys)
{
	size_t n;

	n = keys->capacity * sizeof(Key);
	if(keys->capacity > 0 && n / keys->capacity != sizeof(Key))
		errx(1, "failed to free memory: overflow");
	explicit_bzero(keys->buf, n);
	free(keys->buf);
}

/* Allocate keys->buf for another recepient */
static void
keynew(Keys *keys)
{
	size_t ncap;

	if(keys->len + 1 > keys->capacity) {
		ncap = keys->capacity * 2;
		if(ncap < keys->capacity)	/* overflow */
			errx(1, "number of recipients is too big");
		keys->buf = ereallocarr(keys->buf, ncap, sizeof(Key));
		keys->capacity = ncap;
	}
}

static void
recadd(Keys *recs, char *bech)
{
	int ok;

	keynew(recs);
	ok = x25519pubkey(bech, (uchar *)(recs->buf + recs->len));
	recs->len++;
	if(!ok)
		errx(1, "failed to parse recipient key string %d", recs->len);
}

static int
privadd(Keys *privs, char bech[74+1])
{
	int ok;

	keynew(privs);
	ok = x25519privkey(bech, (uchar *)(privs->buf + privs->len));
	privs->len++;
	return ok;
}

static Data
mkfilekey(void)
{
	Data k;

	k.len = 16;
	k.data = emalloc(k.len);
	if(randombuf(k.data, k.len) == 0)
		errx(1, "failed to generate file key");
	return k;
}

static void
payload(uchar filekey[16], Ibuf *in, Obuf *out)
{
	uchar plkey[32], plnonce[16];
	const char *e;
	int ok;

	ok = randombuf(plnonce, 16);
	if(!ok)
		errx(1, "failed to generate payload nonce");
	payloadkey(filekey, plnonce, plkey);
	bwrite(out, plnonce, sizeof(plnonce));
	e = plencrypt(in, out, plkey);
	if(e)
		errx(1, "failed to encrypt: %s", e);
	explicit_bzero(plkey, sizeof(plkey));
}

static void
passenc(Header *h, Data filekey)
{
	char *pass;

	pass = getpass("Enter passphrase: ");
	if(pass == NULL)
		err(1, "failed to read passphrase");
	scryptstanza(h, filekey, pass);
	explicit_bzero(pass, strlen(pass)); /* TODO: leaks pass length */
}

static void
pubenc(Header *h, Data filekey, Keys *recs)
{
	size_t i;

	for(i = 0; i < recs->len; i++)
		x25519stanza(h, filekey, (uchar *)(recs->buf + i));
}

static ssize_t
skipline(void *b, int encrypted)
{
	ssize_t nr;
	char c;

	for(;;) {
		if(encrypted)
			nr = plread((Ebuf *)b, &c, 1);
		else
			nr = bread((Ibuf *)b, &c, 1);
		if(nr <= 0)
			return nr;
		if(c == '\n')
			return 1;
	}
}

static ssize_t
getkey(void *b, Keys *privs, int encrypted)
{
	char key[74+1], c;
	ssize_t nr;
	int ok;

	nr = encrypted ? plread((Ebuf *)b, key, 74) : bread((Ibuf *)b, key, 74);
	if(nr <= 0)
		return nr;
	if(nr != 74)
		return -2;
	nr = encrypted ? plread((Ebuf *)b, &c, 1) : bread((Ibuf *)b, &c, 1);
	if(nr == -1)
		return -1;
	if(nr == 1 && c != '\n')
		return -2;
	ok = privadd(privs, key);
	if(!ok)
		return -2;
	if(nr == 0)
		return 0;
	return 1;
}

static void
readprivkeys(Keys *privs, const char *path)
{
	int fd;
	Ibuf ib;
	Ebuf eb;
	void *in = &ib;
	ssize_t nr;
	int lineno;
	char c;
	int encrypted = 0;

	fd = open(path, O_RDONLY);
	if(fd == -1)
		err(1, "failed to open key file");
	ibinit(&ib, fd);
	encrypted = checkencrypted(&ib, &eb);
	if(encrypted)
		in = &eb;
	for(lineno = 1; ; lineno++) {
		nr = encrypted ? plpeek(&eb, &c) : bpeek(&ib, &c);
		if(nr == -1)
			err(1, "failed to read key file");
		if(nr == 0)
			break;
		if(c == '#') {
			nr = skipline(in, encrypted);
			if(nr == -1)
				err(1, "failed to read key file");
			if(nr == 0)
				break;
			continue;
		}
		nr = getkey(in, privs, encrypted);
		if(nr == -1)
			err(1, "failed to read key file");
		if(nr == -2)
			errx(1, "invalid private key at line %d",
					lineno);
		if(nr == 0)
			break;
	}
	if(encrypted)
		plfree(&eb);
	ibfree(&ib);
}

static int
checkencrypted(Ibuf *ib, Ebuf *eb)
{
	uchar filekey[16], plnonce[16], plkey[32];
	Stanza s;
	ssize_t nr;
	char c;
	const char *e;

	nr = bpeek(ib, &c);
	if(nr == -1)
		err(1, "failed to read key file");
	if(nr == 0 || c != 'a')
		return 0;
	e = getversion(ib);
	if(e)
		errx(1, "invalid private key at line %d", 1);
	matchscrypt(ib, &s);
	scryptkey(filekey, &s);
	validatemac(ib, filekey);
	e = getplnonce(ib, plnonce);
	if(e)
		errx(1, "failed to decrypt key file: %s", e);
	payloadkey(filekey, plnonce, plkey);
	plinit(eb, ib, plkey);
	return 1;
}

static void
matchscrypt(Ibuf *ib, Stanza *s)
{
	uchar filekey[16];
	Keys nilkeys;
	int found;

	nilkeys.len = 0;
	match(ib, filekey, s, &nilkeys, &found);
	if(!found || s->type != SCRYPT)
		errx(1, "failed to read key file: scrypt identity not found");
}

static void
encipher(Ibuf *in, Obuf *out, int ispass, Keys *recs)
{
	Header h;
	Data filekey;
	char mac[B64EBUFLEN(32)];
	size_t maclen;

	hdrinit(&h);
	hdrappend(&h, "age-encryption.org/v1\n");
	filekey = mkfilekey();
	if(ispass)
		passenc(&h, filekey);
	else
		pubenc(&h, filekey, recs);
	hdrappend(&h, "---");
	hdrmac(h.data, h.len, filekey, mac, &maclen);
	if(out->isarmor)
		write(out->fd, armorfirst, sizeof(armorfirst) - 1);
	hdrappend(&h, " %s\n", mac);
	bwrite(out, h.data, h.len);
	payload(filekey.data, in, out);
	bflush(out);
	if(out->isarmor)
		write(out->fd, armorlast, sizeof(armorlast) - 1);
	explicit_bzero(filekey.data, filekey.len);
	free(filekey.data);
	free(h.data);
}

static const char *
validmac(Ibuf *in, uchar filekey[16], int *isvalid)
{
	uchar mac1[32], mac2[32];
	static const char *e;
	uchar *data;
	Data fk;
	size_t len;

	data = recstop(in, &len);
	e = getmac(in, mac1);
	if(e)
		return e;
	fk.data = filekey;
	fk.len = 16;
	mac(data, len, fk, mac2);
	*isvalid = memcmp(mac1, mac2, 32) == 0;
	return NULL;
}

static void
decipher(Ibuf *in, Obuf *out, Keys *ids)
{
	const char *e;
	uchar filekey[16], plnonce[16], plkey[32];
	Stanza s;
	int found;

	e = getversion(in);
	if(e)
		errx(1, "error parsing header: %s", e);
	match(in, filekey, &s, ids, &found);
	if(!found)
		errx(1, "no identity matched any of the recipients");
	if(s.type == SCRYPT)
		scryptkey(filekey, &s);
	validatemac(in, filekey);
	e = getplnonce(in, plnonce);
	if(e)
		errx(1, "failed to decrypt: %s", e);
	payloadkey(filekey, plnonce, plkey);
	e = pldecrypt(in, out, plkey);
	if(e)
		errx(1, "failed to decrypt: %s", e);
	bflush(out);
}

/* filekey is filled only if X25519 id is found */
static void
match(Ibuf *in, uchar filekey[16], Stanza *s, Keys *ids, int *found)
{
	const char *e;
	int end, seenscrypt, n;
	unsigned i;

	for(n = seenscrypt = *found = 0;; n++) {
		e = getstanza(in, s, &end);
		if(e)
			errx(1, "error parsing header: %s", e);
		if(end)
			break;
		if(s->type == SCRYPT) {
			seenscrypt = *found = 1;
		} else if(s->type == X25519 && !*found) {
			for(i = 0; i < ids->len && !*found; i++) {
				*found = x25519getkey(filekey, &s->x25519,
						ids->buf[i].r);
			}
		}
	}
	if(n > 1 && seenscrypt)
		errx(1, "invalid input: scrypt recipient is not the only one");
}

static void
scryptkey(uchar filekey[16], Stanza *s)
{
	char *pass;
	int ok;

	if(s->scrypt.cost > SCRYPTMAXCOST)
		errx(1, "rejecting to decrypt: scrypt work factor is too big");
	pass = getpass("Enter passphrase: ");
	if(pass == NULL)
		err(1, "failed to read passphrase");
	ok = scryptgetkey(filekey, &s->scrypt, pass);
	if(!ok)
		errx(1, "failed to decrypt: invalid passphrase");
	explicit_bzero(pass, strlen(pass)); /* TODO: leaks pass length */
}

static void
validatemac(Ibuf *in, uchar filekey[16])
{
	const char *e;
	int valid;

	e = validmac(in, filekey, &valid);
	if(e)
		errx(1, "failed to decrypt: error parsing header: %s", e);
	if(!valid)
		errx(1, "failed to decrypt: bad header MAC");
}

int
main(int argc, char *argv[])
{
	Ibuf ib;
	Obuf ob;
	Keys recs, ids;
	int pflag = 0, dflag = 0;
	const char *idpath = NULL;
	int ch, fd;

	argv0 = argv[0] ? argv[0] : "cage";
	keyinit(&recs);
	ob.isarmor = 0;
	while((ch = getopt(argc, argv, "adi:pr:")) != -1) {
		switch(ch) {
		case 'a':
			ob.isarmor = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'i':
			if(idpath) {
				keyfree(&recs);
				usage();
			}
			idpath = optarg;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'r':
			recadd(&recs, optarg);
			break;
		default:
			keyfree(&recs);
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if(!dflag && pflag && recs.len > 0)
		goto badusage;
	if(!dflag && !pflag && recs.len == 0)
		goto badusage;
	if(argc == 1) {
		fd = open(argv[0], O_RDONLY);
		if(fd == -1)
			err(1, "failed to open input file");
		ibinit(&ib, fd);
	} else if(argc == 0) {
		ibinit(&ib, 0);
	} else {
		goto badusage;
	}
	ob.cur = 0;
	ob.fd = 1;
	if(dflag) {
		if(pflag || recs.len || ob.isarmor)
			goto badusage;
		if(idpath) {
			keyinit(&ids);
			readprivkeys(&ids, idpath);
		}
		decipher(&ib, &ob, &ids);
		if(idpath)
			keyfree(&ids);
	} else {
		if(idpath)
			goto badusage;
		encipher(&ib, &ob, pflag, &recs);
	}
	explicit_bzero(&ob, sizeof(ob));
	keyfree(&recs);
	ibfree(&ib);
	return 0;
badusage:
	explicit_bzero(&ob, sizeof(ob));
	keyfree(&recs);
	ibfree(&ib);
	usage();
}
